#!/usr/bin/env python3
"""
opmonitor_probe.py — test pobrania surowego wideo przez OPMonitor (DVRIP, port 34567),
zamiast RTSP (port 554). Wzorzec 1:1 wzięty z go2rtc (pkg/dvrip/client.go, producer.go,
AlexxIT/go2rtc na GitHubie) — message ID i format ramki wideo potwierdzone tam,
zgadzają się z naszym własnym rozpoznaniem z Fazy 1 (Wireshark, natywna appka Windows).

Sekwencja:
  1. Login (sofia-hash, jak reszta naszych skryptów)
  2. OPMonitorClaim (msg 1413) — zarezerwuj strumień dla kanału
  3. OPMonitorStart (msg 1410) — start, od tego momentu socket leci surowym A/V
  4. Odczyt "surowych" pakietów: prefiks b'\\x00\\x00\\x01' + bajt typu + rozmiar
     (0xFC/0xFE = I-frame/config, 0xFD = P-frame, 0xFA = audio) — format z go2rtc.

Użycie:
    python3 opmonitor_probe.py --host 192.168.1.100 --user tester --password 'HASLO!' --channel 3
    (channel liczone OD 0, jak w OPMonitor/AlarmInfo — kanał fizyczny 4 to channel=3)
"""

import argparse
import hashlib
import json
import socket
import struct
import sys

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_OPMONITOR_CLAIM = 1413
MSG_OPMONITOR_START = 1410


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


class RawClient:
    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.session_id = 0
        self.sequence = 0

    def send(self, msg_id: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0x00, self.session_id, self.sequence, msg_id, len(body))
        self.sock.sendall(header + body)
        self.sequence += 1

    def recv_json(self) -> dict:
        header_raw = self._recv_exact(HEADER_LEN)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        payload_raw = self._recv_exact(plen) if plen else b""
        text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
        return json.loads(text)

    def _recv_exact(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("połączenie zamknięte przez urządzenie")
            data += chunk
        return data

    def login(self, user: str, password: str) -> dict:
        self.send(MSG_LOGIN_REQ, {
            "EncryptType": "MD5",
            "LoginType": "DVRIP-Web",
            "PassWord": sofia_hash(password),
            "UserName": user,
        })
        data = self.recv_json()
        if data.get("Ret") not in (100, "100"):
            raise RuntimeError(f"login odrzucony: {data}")
        self.session_id = int(data["SessionID"], 16)
        return data


def read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("połączenie zamknięte")
        data += chunk
    return data


def read_dvrip_chunk(sock: socket.socket) -> bytes:
    """1:1 port `ReadChunk()` z go2rtc (pkg/dvrip/client.go): nawet surowe wideo/audio
    jest owinięte w standardowy 20-bajtowy nagłówek DVRIP (head=0xFF) — payload to
    fragment (~32KB) wewnętrznej ramki A/V, do sklejenia w read_raw_packet()."""
    header = read_exact(sock, HEADER_LEN)
    if header[0] != 0xFF:
        raise ValueError(f"zły head w chunku: {header[:20]!r}")
    _, version, _, _, msg_id, size = struct.unpack(HEADER_FMT, header)
    print(f"    [chunk] version={version} msg_id={msg_id} size={size}")
    return read_exact(sock, size)


def read_raw_packet(sock: socket.socket, buf: bytearray, timeout: float = 5.0):
    """1:1 port `ReadPacket()` z go2rtc: skleja kolejne chunki (read_dvrip_chunk) aż
    uzbiera się cała ramka A/V (prefiks 00 00 01 + typ + rozmiar wewnętrzny)."""
    sock.settimeout(timeout)

    while len(buf) < 16:
        buf.extend(read_dvrip_chunk(sock))

    if bytes(buf[:3]) != b"\x00\x00\x01":
        raise ValueError(f"zły prefiks ramki A/V: {bytes(buf[:16])!r}")

    ptype = buf[3]
    if ptype in (0xFC, 0xFE):
        size = struct.unpack_from("<I", buf, 12)[0] + 16
    elif ptype == 0xFD:
        size = struct.unpack_from("<I", buf, 4)[0] + 8
    elif ptype in (0xFA, 0xF9):
        size = struct.unpack_from("<H", buf, 6)[0] + 8
    else:
        raise ValueError(f"nieznany typ ramki: 0x{ptype:02X}")

    while len(buf) < size:
        buf.extend(read_dvrip_chunk(sock))

    payload = bytes(buf[:size])
    del buf[:size]
    return ptype, payload


def main():
    ap = argparse.ArgumentParser(description="Test pobrania wideo przez OPMonitor (jak go2rtc)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, default=3, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--stream-type", default="Main", choices=["Main", "Extra1"])
    ap.add_argument("--packets", type=int, default=10, help="ile pakietów odebrać przed końcem")
    ap.add_argument("--timeout", type=float, default=20.0, help="timeout gniazda przy odbiorze wideo (s)")
    ap.add_argument("--save", help="zapisz surowe payloady wideo (I/P-frame) do pliku .h265")
    args = ap.parse_args()

    client = RawClient(args.host, args.port)
    login_data = client.login(args.user, args.password)
    print(f"Zalogowano, SessionID=0x{client.session_id:08X}, DeviceType={login_data.get('DeviceType ')}")

    stream_param = {
        "Channel": args.channel,
        "CombinMode": "NONE",
        "StreamType": args.stream_type,
        "TransMode": "TCP",
    }

    print(f"\n--- OPMonitor Claim (kanał {args.channel}, {args.stream_type}) ---")
    client.send(MSG_OPMONITOR_CLAIM, {
        "Name": "OPMonitor",
        "SessionID": f"0x{client.session_id:08X}",
        "OPMonitor": {"Action": "Claim", "Parameter": stream_param},
    })
    claim_resp = client.recv_json()
    print(json.dumps(claim_resp, ensure_ascii=False))
    if claim_resp.get("Ret") not in (100, "100"):
        print("Claim nieudany, przerywam.")
        sys.exit(1)

    print("\n--- OPMonitor Start ---")
    client.send(MSG_OPMONITOR_START, {
        "Name": "OPMonitor",
        "SessionID": f"0x{client.session_id:08X}",
        "OPMonitor": {"Action": "Start", "Parameter": stream_param},
    })

    print(f"\n--- Odbiór surowych pakietów (do {args.packets}) ---")
    buf = bytearray()
    video_frames = []
    counts = {}
    try:
        for i in range(args.packets):
            ptype, payload = read_raw_packet(client.sock, buf, timeout=args.timeout)
            label = {0xFC: "I-frame/config", 0xFE: "I-frame/config",
                     0xFD: "P-frame", 0xFA: "audio", 0xF9: "unknown(F9)"}.get(ptype, f"0x{ptype:02X}")
            counts[label] = counts.get(label, 0) + 1
            print(f"  [{i}] typ=0x{ptype:02X} ({label}) rozmiar={len(payload)}B  pierwsze bajty={payload[:12].hex()}")
            if ptype in (0xFC, 0xFE, 0xFD):
                video_frames.append((ptype, payload))
    except (socket.timeout, ConnectionError, ValueError) as e:
        print(f"  przerwano odbiór: {e}")

    print(f"\n=== Podsumowanie: {sum(counts.values())} pakietów, {dict(counts)} ===")

    if video_frames:
        print(f"\nSUKCES: odebrano {len(video_frames)} pakietów wideo przez OPMonitor.")
        if args.save:
            with open(args.save, "wb") as f:
                for ptype, payload in video_frames:
                    # I-frame (0xFC/0xFE): payload[16:] to Annex-B NAL units (jak w go2rtc producer.go)
                    # P-frame (0xFD): payload[8:]
                    body = payload[16:] if ptype in (0xFC, 0xFE) else payload[8:]
                    f.write(body)
            print(f"Zapisano surowy strumień do {args.save}")
    else:
        print("\nBRAK pakietów wideo — OPMonitor nie zadziałał tak jak oczekiwano.")


if __name__ == "__main__":
    main()
