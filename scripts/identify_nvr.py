#!/usr/bin/env python3
"""
identify_nvr.py — identyfikacja rejestratora XMEYE (NetSurveillance/DVRIP/Sofia)

Cel: zebrać jak najwięcej informacji o konkretnym rejestratorze (model, firmware,
chipset, liczba kanałów, otwarte porty) PRZED przystąpieniem do budowy integracji HA.
To jest Faza 0 z PROTOCOL_NOTES.md in the ha-xmeye-nvr repo.

UWAGA: implementacja protokołu DVRIP (port 34567) jest oparta o wiedzę community
(dvrip-py i pochodne) — nie jest pewne, że message ID i hash logowania pasują 1:1
do Twojego konkretnego firmware. Skrypt jest napisany tak, żeby mimo błędów w tych
założeniach i tak zwrócił użyteczne dane (skan portów, banner HTTP) oraz surowe bajty
odpowiedzi, które można później porównać z zrzutem Wireshark z Fazy 0.

Użycie:
    python3 identify_nvr.py --host 192.168.1.100 --user admin --password TWOJEHASLO

Zależności: tylko standardowa biblioteka Pythona (socket, struct, hashlib, json).
"""

import argparse
import hashlib
import json
import socket
import struct
import sys
import time

DVRIP_PORT = 34567
HEADER_FMT = "<BB2xII2xHI"   # head, version, [pad2], session_id, sequence, [pad2], msg_id, payload_len
HEADER_LEN = struct.calcsize(HEADER_FMT)

# Message ID znane z community (dvrip-py i pochodne) — mogą wymagać korekty per firmware.
MSG_LOGIN_REQ = 1000
MSG_LOGIN_RESP = 1001
MSG_SYSINFO_REQ = 1020
MSG_SYSINFO_RESP = 1021
MSG_KEEPALIVE_REQ = 1006
MSG_LOGOUT_REQ = 1001

# Generyczna komenda "config get" — znana z community (python-dvr/OpenIPC), pozwala
# odpytać dowolny nazwany blok konfiguracji przez pole "Name" w payloadzie.
MSG_CONFIG_GET = 1042
# "ChannelTitle" ma własny, dedykowany kod GET (inny niż generyczny 1042).
MSG_CHANNEL_TITLE_GET = 1048

COMMON_PORTS = {
    34567: "DVRIP/XMEYE control",
    34599: "DVRIP alt/second instance",
    554: "RTSP (podgląd wideo)",
    80: "HTTP (panel web)",
    8000: "HTTP alt / niektóre panele",
    37777: "Dahua DVRIP (jeśli OEM od Dahua)",
    8899: "Czasem P2P/cloud discovery",
}


def sofia_hash(password: str) -> str:
    """Znany z community algorytm hashowania hasła używany przez XMEye/Sofia."""
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    result = []
    for i in range(8):
        n = (md5_digest[2 * i] + md5_digest[2 * i + 1]) % 62
        result.append(chars[n])
    return "".join(result)


def scan_ports(host: str, ports: dict, timeout: float = 1.0) -> dict:
    """Prosty skan wskazanych portów TCP, zwraca {port: True/False}."""
    results = {}
    for port, label in ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            results[port] = {"open": True, "label": label}
        except OSError:
            results[port] = {"open": False, "label": label}
        finally:
            s.close()
    return results


def grab_http_banner(host: str, port: int, timeout: float = 2.0) -> str | None:
    """Próba pobrania nagłówków HTTP z panelu web (jeśli port otwarty)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        req = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        s.sendall(req.encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 8192:
                break
        s.close()
        return data.decode(errors="replace")
    except OSError:
        return None


class DVRIPClient:
    """Minimalny klient protokołu DVRIP do celów identyfikacji (nie do produkcji)."""

    def __init__(self, host: str, port: int = DVRIP_PORT, timeout: float = 3.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.session_id = 0
        self.sequence = 0

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()

    def _send(self, msg_id: int, payload: dict):
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(
            HEADER_FMT, 0xFF, 0x00, self.session_id, self.sequence, msg_id, len(body)
        )
        self.sock.sendall(header + body)
        self.sequence += 1

    def _recv(self):
        header_raw = self._recv_exact(HEADER_LEN)
        if header_raw is None:
            return None, None, None
        head, version, session_id, sequence, msg_id, payload_len = struct.unpack(
            HEADER_FMT, header_raw
        )
        payload_raw = self._recv_exact(payload_len) if payload_len else b""
        return msg_id, payload_raw, header_raw

    def _recv_exact(self, n: int):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    def login(self, user: str, password: str):
        payload = {
            "EncryptType": "MD5",
            "LoginType": "DVRIP-Web",
            "PassWord": sofia_hash(password),
            "UserName": user,
        }
        self._send(MSG_LOGIN_REQ, payload)
        msg_id, payload_raw, header_raw = self._recv()
        parsed = None
        try:
            text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
            parsed = json.loads(text)
        except Exception:
            pass
        if parsed:
            self.session_id = int(parsed.get("SessionID", "0x0"), 16) if isinstance(
                parsed.get("SessionID"), str
            ) else self.session_id
        return msg_id, parsed, header_raw, payload_raw

    def query_sysinfo(self):
        payload = {
            "Name": "SystemInfo",
            "SessionID": f"0x{self.session_id:08X}",
        }
        self._send(MSG_SYSINFO_REQ, payload)
        msg_id, payload_raw, header_raw = self._recv()
        parsed = None
        try:
            text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
            parsed = json.loads(text)
        except Exception:
            pass
        return msg_id, parsed, header_raw, payload_raw

    def get_named_config(self, msg_id: int, name: str):
        """Zapytanie o dowolny nazwany blok configu (wzorzec z community: msg 1042
        = generyczny "config get", niektóre nazwy jak ChannelTitle mają własny kod)."""
        payload = {
            "Name": name,
            "SessionID": f"0x{self.session_id:08X}",
        }
        self._send(msg_id, payload)
        resp_msg_id, payload_raw, header_raw = self._recv()
        parsed = None
        try:
            text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
            parsed = json.loads(text)
        except Exception:
            pass
        return resp_msg_id, parsed, header_raw, payload_raw

    def get_channel_status(self):
        return self.get_named_config(MSG_CONFIG_GET, "NetWork.ChnStatus")

    def get_channel_titles(self):
        return self.get_named_config(MSG_CHANNEL_TITLE_GET, "ChannelTitle")


def main():
    ap = argparse.ArgumentParser(description="Identyfikacja rejestratora XMEYE")
    ap.add_argument("--host", required=True, help="IP rejestratora")
    ap.add_argument("--user", required=True, help="użytkownik (zwykle admin)")
    ap.add_argument("--password", required=True, help="hasło")
    ap.add_argument("--dvrip-port", type=int, default=DVRIP_PORT)
    args = ap.parse_args()

    print(f"=== Identyfikacja rejestratora: {args.host} ===\n")

    print("--- Skan portów ---")
    port_results = scan_ports(args.host, COMMON_PORTS)
    for port, info in sorted(port_results.items()):
        status = "OTWARTY" if info["open"] else "zamknięty/brak odpowiedzi"
        print(f"  {port:>6} ({info['label']}): {status}")
    print()

    if port_results.get(80, {}).get("open") or port_results.get(8000, {}).get("open"):
        http_port = 80 if port_results.get(80, {}).get("open") else 8000
        print(f"--- Banner HTTP (port {http_port}) ---")
        banner = grab_http_banner(args.host, http_port)
        if banner:
            # tylko nagłówki, żeby nie zaśmiecać outputu całym HTML
            head = banner.split("\r\n\r\n", 1)[0]
            print(head)
        else:
            print("  brak odpowiedzi / błąd połączenia")
        print()

    if not port_results.get(args.dvrip_port, {}).get("open"):
        print(f"Port {args.dvrip_port} (DVRIP) zamknięty — pomijam próbę logowania protokołem XMEYE.")
        print("Sprawdź czy IP/port się zgadza, ewentualnie użyj --dvrip-port.")
        return

    print(f"--- Próba logowania DVRIP (port {args.dvrip_port}) ---")
    client = DVRIPClient(args.host, args.dvrip_port)
    try:
        client.connect()
    except OSError as e:
        print(f"  Błąd połączenia: {e}")
        return

    try:
        msg_id, parsed, header_raw, payload_raw = client.login(args.user, args.password)
        print(f"  Odebrano msg_id={msg_id}")
        if parsed:
            print("  Odpowiedź (JSON):")
            print(json.dumps(parsed, indent=2, ensure_ascii=False))
        else:
            print("  Nie udało się sparsować JSON — surowe bajty odpowiedzi:")
            print(f"    header: {header_raw!r}")
            print(f"    payload: {payload_raw!r}")
            print("  (to jest normalne jeśli message ID/hash różni się w tym firmware —")
            print("   porównaj te bajty ze zrzutem Wireshark z oficjalnej aplikacji)")
            client.close()
            return

        if parsed and parsed.get("Ret") not in (100, "100"):
            print(f"\n  Logowanie nieudane (Ret={parsed.get('Ret')}). Sprawdź user/hasło")
            print("  lub porównaj format żądania ze zrzutem ruchu oficjalnej aplikacji.")
            client.close()
            return

        print("\n--- Zapytanie o SystemInfo ---")
        time.sleep(0.2)
        msg_id2, parsed2, header_raw2, payload_raw2 = client.query_sysinfo()
        if parsed2:
            print(json.dumps(parsed2, indent=2, ensure_ascii=False))
        else:
            print("  Brak/nieparsowalna odpowiedź — surowe bajty:")
            print(f"    header: {header_raw2!r}")
            print(f"    payload: {payload_raw2!r}")

    except socket.timeout:
        print("  Timeout — brak odpowiedzi od rejestratora w tym formacie protokołu.")
    except Exception as e:
        print(f"  Nieoczekiwany błąd: {e}")
    finally:
        client.close()

    print("\n=== Koniec ===")
    print("Jeśli logowanie/SystemInfo się nie udało: przechwyć ruch oficjalnej appki")
    print("Wiresharkiem i porównaj message ID / format hasła z tym, co jest w skrypcie —")
    print("to jest dokładnie Faza 0 z PROTOCOL_NOTES.md in the ha-xmeye-nvr repo.")


if __name__ == "__main__":
    main()
