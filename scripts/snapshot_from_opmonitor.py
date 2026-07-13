#!/usr/bin/env python3
"""
snapshot_from_opmonitor.py — pobranie JEDNEGO zdjęcia z kanału rejestratora XMEYE.

UWAGA: `OPSNAP` (dedykowana komenda DVRIP do snapshotów, msg_id 1560) jest
ZABLOKOWANA na Rejestratorze #1 — konsekwentnie zwraca `Ret=108` (kod błędu spoza
znanego zestawu z community, niezależny od kanału i od tego, czy `OPMonitor` jest
aktywnie zaklejmowany na tym samym połączeniu; NIE jest to problem uprawnień —
konto testowe ma pełną listę `AuthorityList` identyczną z kontami admina). Patrz
`snapshot_probe.py` i PROTOCOL_NOTES.md in the ha-xmeye-nvr repo po szczegóły tej ślepej uliczki.

Działająca alternatywa (ten skrypt): `OPMonitorClaim`+`OPMonitorStart` (wzorzec z
go2rtc, potwierdzony w `opmonitor_probe.py`), złap pierwszą kompletną klatkę I-frame
(H265), zdekoduj do obrazu przez PyAV (bundluje własny FFmpeg, nie wymaga sudo/apt).

Zależności (NIE tylko standardowa biblioteka, w przeciwieństwie do reszty skryptów
w repo): `pip install av pillow`.

Użycie:
    python3 snapshot_from_opmonitor.py --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 --out snapshot.jpg
    (channel liczone OD 0, jak OPMonitor/AlarmInfo — kanał fizyczny 4 = channel 3)
"""

import argparse
import hashlib
import io
import json
import socket
import struct
import sys

try:
    import av
except ImportError:
    print("Brakuje pakietu 'av' (PyAV). Zainstaluj: pip install av pillow")
    sys.exit(1)

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_OPMONITOR_CLAIM = 1413
MSG_OPMONITOR_START = 1410


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


def read_exact(sock: socket.socket, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("połączenie zamknięte")
        data += chunk
    return data


def read_dvrip_chunk(sock: socket.socket) -> bytes:
    """Nawet surowe wideo jest owinięte w standardowy 20-bajtowy nagłówek DVRIP —
    payload to fragment (~32KB) większej ramki A/V, patrz opmonitor_probe.py/PROTOCOL_NOTES.md in the ha-xmeye-nvr repo."""
    header = read_exact(sock, HEADER_LEN)
    if header[0] != 0xFF:
        raise ValueError(f"zły head w chunku: {header[:20]!r}")
    _, _, _, _, _, size = struct.unpack(HEADER_FMT, header)
    return read_exact(sock, size)


def read_one_iframe(sock: socket.socket, timeout: float) -> bytes:
    """Zwraca surowe bajty Annex-B (VPS+SPS+PPS+IDR) pierwszej kompletnej klatki I."""
    sock.settimeout(timeout)
    buf = bytearray()
    while True:
        while len(buf) < 16:
            buf.extend(read_dvrip_chunk(sock))
        if bytes(buf[:3]) != b"\x00\x00\x01":
            raise ValueError(f"zły prefiks ramki A/V: {bytes(buf[:16])!r}")
        ptype = buf[3]
        if ptype in (0xFC, 0xFE):
            size = struct.unpack_from("<I", buf, 12)[0] + 16
            header_len = 16
        elif ptype == 0xFD:
            size = struct.unpack_from("<I", buf, 4)[0] + 8
            header_len = 8
        elif ptype in (0xFA, 0xF9):
            size = struct.unpack_from("<H", buf, 6)[0] + 8
            header_len = 8
        else:
            raise ValueError(f"nieznany typ ramki: 0x{ptype:02X}")

        while len(buf) < size:
            buf.extend(read_dvrip_chunk(sock))

        payload = bytes(buf[:size])
        del buf[:size]

        if ptype in (0xFC, 0xFE):
            return payload[header_len:]  # Annex-B: VPS+SPS+PPS+IDR


def main():
    ap = argparse.ArgumentParser(description="Pobranie jednego zdjęcia z rejestratora XMEYE (przez OPMonitor)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, default=3, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--stream-type", default="Extra1", choices=["Main", "Extra1"],
                     help="Extra1 (substream) jest dużo bardziej niezawodny na tym sprzęcie niż Main")
    ap.add_argument("--out", default="snapshot.jpg")
    ap.add_argument("--timeout", type=float, default=20.0)
    args = ap.parse_args()

    sock = socket.create_connection((args.host, args.port), timeout=args.timeout)
    session_id = 0
    sequence = 0

    def send(msg_id: int, payload: dict) -> None:
        nonlocal sequence
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0x00, session_id, sequence, msg_id, len(body))
        sock.sendall(header + body)
        sequence += 1

    def recv_json() -> dict:
        header_raw = read_exact(sock, HEADER_LEN)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        payload_raw = read_exact(sock, plen) if plen else b""
        return json.loads(payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace"))

    send(MSG_LOGIN_REQ, {
        "EncryptType": "MD5", "LoginType": "DVRIP-Web",
        "PassWord": sofia_hash(args.password), "UserName": args.user,
    })
    login_data = recv_json()
    if login_data.get("Ret") not in (100, "100"):
        print(f"Logowanie nieudane: {login_data}")
        sys.exit(1)
    session_id = int(login_data["SessionID"], 16)
    print(f"Zalogowano, SessionID=0x{session_id:08X}")

    stream_param = {
        "Channel": args.channel, "CombinMode": "NONE",
        "StreamType": args.stream_type, "TransMode": "TCP",
    }
    send(MSG_OPMONITOR_CLAIM, {
        "Name": "OPMonitor", "SessionID": f"0x{session_id:08X}",
        "OPMonitor": {"Action": "Claim", "Parameter": stream_param},
    })
    claim_resp = recv_json()
    if claim_resp.get("Ret") not in (100, "100"):
        print(f"OPMonitor Claim nieudany: {claim_resp}")
        sys.exit(1)

    send(MSG_OPMONITOR_START, {
        "Name": "OPMonitor", "SessionID": f"0x{session_id:08X}",
        "OPMonitor": {"Action": "Start", "Parameter": stream_param},
    })

    print("Czekam na pierwszą kompletną klatkę I-frame...")
    h265_data = read_one_iframe(sock, args.timeout)
    print(f"Odebrano {len(h265_data)} bajtów H265 (Annex-B).")

    container = av.open(io.BytesIO(h265_data), format="hevc")
    frame = next(container.decode(video=0))
    print(f"Zdekodowano klatkę: {frame.width}x{frame.height} ({frame.format.name})")
    frame.to_image().save(args.out, quality=90)
    print(f"Zapisano zdjęcie do {args.out}")


if __name__ == "__main__":
    main()
