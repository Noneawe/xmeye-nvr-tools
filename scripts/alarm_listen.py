#!/usr/bin/env python3
"""
alarm_listen.py — nasłuch push AlarmInfo (ruch/twarz/human detection) w czasie
rzeczywistym, naszym prostym klientem DVRIP (plain-JSON login, sofia-hash MD5).

Kontekst (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo): zrzut Wireshark z oficjalnej appki Windows potwierdził,
że AlarmInfo (msg_id 1504) faktycznie przychodzi jako push, ale w tamtej sesji
payload był zaszyfrowany (appka Windows loguje się trybem RSA). Ten skrypt loguje
się NASZYM prostym sposobem (ten sam co identify_nvr.py/channel_status.py — już
potwierdzony jako działający) w nadziei, że przy tym trybie logowania AlarmInfo
przyjdzie jako czytelny JSON, zamiast szyfrogramu.

Wzorzec subskrypcji (`AlarmSet` z pustym "Name") wzięty z community (python-dvr,
metoda `alarmStart()`): wysyła msg_id 1500 {"Name": "", "SessionID": "0x..."},
po czym serwer ma zacząć pchać AlarmInfo (msg_id 1504) na tym samym połączeniu.

Użycie:
    python3 alarm_listen.py --host 192.168.1.100 --user tester --password 'HASLO!' --duration 90

W trakcie działania: wywołaj alarm fizycznie (ruch/twarz przed kamerą na kanale 4 lub 5).
"""

import argparse
import json
import socket
import sys
import time

from identify_nvr import DVRIPClient

MSG_ALARM_SET_REQ = 1500
MSG_ALARM_SET_RESP = 1501
MSG_ALARM_INFO = 1504
MSG_KEEPALIVE_REQ = 1006
MSG_KEEPALIVE_RESP = 1007


def main():
    ap = argparse.ArgumentParser(description="Nasłuch AlarmInfo (push) na rejestratorze XMEYE")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--dvrip-port", type=int, default=34567)
    ap.add_argument("--duration", type=float, default=90.0, help="jak długo nasłuchiwać, w sekundach")
    args = ap.parse_args()

    client = DVRIPClient(args.host, args.dvrip_port, timeout=5.0)
    try:
        client.connect()
    except OSError as e:
        print(f"Błąd połączenia: {e}")
        sys.exit(1)

    _, login_parsed, _, _ = client.login(args.user, args.password)
    if not login_parsed or login_parsed.get("Ret") not in (100, "100"):
        print(f"Logowanie nieudane: {login_parsed}")
        sys.exit(1)
    print(f"Zalogowano, SessionID=0x{client.session_id:08X}")

    # Subskrypcja alarmów: msg 1500, {"Name": "", "SessionID": "0x..."} (wzorzec community)
    client._send(MSG_ALARM_SET_REQ, {"Name": "", "SessionID": f"0x{client.session_id:08X}"})
    msg_id, payload_raw, _ = client._recv()
    try:
        resp = json.loads(payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace"))
    except Exception:
        resp = None
    print(f"AlarmSet subskrypcja: msg_id={msg_id}, odpowiedź={resp}")
    if not resp or resp.get("Ret") not in (100, "100"):
        print("UWAGA: subskrypcja alarmów nie potwierdzona Ret=100 — nasłuchuję mimo to.")

    print(f"\nNasłuchuję przez {args.duration:.0f}s — wywołaj teraz alarm (ruch/twarz przed kamerą)...\n")

    client.sock.settimeout(2.0)
    deadline = time.time() + args.duration
    last_keepalive = time.time()
    event_count = 0

    while time.time() < deadline:
        if time.time() - last_keepalive > 15:
            try:
                client._send(MSG_KEEPALIVE_REQ, {"Name": "KeepAlive", "SessionID": f"0x{client.session_id:08X}"})
            except OSError:
                pass
            last_keepalive = time.time()

        try:
            msg_id, payload_raw, _ = client._recv()
        except socket.timeout:
            continue
        except OSError as e:
            print(f"Błąd gniazda: {e}")
            break
        if msg_id is None:
            print("Połączenie zamknięte przez serwer.")
            break

        if msg_id == MSG_KEEPALIVE_RESP:
            continue

        try:
            text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
            parsed = json.loads(text)
        except Exception:
            parsed = None

        if msg_id == MSG_ALARM_INFO:
            event_count += 1
            print(f"--- AlarmInfo #{event_count} (t={time.time():.2f}) ---")
            if parsed:
                print(json.dumps(parsed, indent=2, ensure_ascii=False))
            else:
                print("Nie udało się sparsować jako JSON — surowe bajty:")
                print(f"  {payload_raw!r}")
        else:
            print(f"[inna ramka] msg_id={msg_id} len={len(payload_raw)}"
                  + (f" {json.dumps(parsed, ensure_ascii=False)[:200]}" if parsed else ""))

    print(f"\n=== Koniec nasłuchu. Złapano {event_count} zdarzeń AlarmInfo. ===")
    client.close()


if __name__ == "__main__":
    main()
