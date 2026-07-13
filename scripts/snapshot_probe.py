#!/usr/bin/env python3
"""
snapshot_probe.py — pobranie pojedynczego zdjęcia (JPEG) przez DVRIP, komenda OPSNAP
(msg_id 1560). Wzorzec wzięty z community (python-dvr, metody snapshot() i
reassemble_bin_payload()) — inny wariant 20-bajtowego nagłówka niż zwykłe komendy
JSON: bajty 12-13 to nie padding, tylko (total_chunks, cur_chunk), reszta layoutu
taka sama. Treść zaczyna się od magicznych bajtów JPEG (FFD8FFE0/FFD8FFDB).

WYNIK (udokumentowany ślepy zaułek, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo): na Rejestratorze #1 OPSNAP
konsekwentnie zwraca `Ret=108` — sprawdzone na kilku kanałach, z i bez aktywnego
OPMonitor Claim, to NIE jest problem uprawnień (konto ma pełną listę AuthorityList
jak admin). Firmware po prostu nie obsługuje/blokuje tę komendę, z nieznanego powodu.
Działająca alternatywa: `snapshot_from_opmonitor.py` (OPMonitor + dekodowanie H265).

Użycie:
    python3 snapshot_probe.py --host 192.168.1.100 --user tester --password 'HASLO!' \
        --channel 3 --out snapshot.jpg
    (channel liczone OD 0, jak OPMonitor/AlarmInfo — kanał fizyczny 4 = channel 3)
"""

import argparse
import hashlib
import json
import socket
import struct
import sys

HEADER_FMT = "<BB2xII2xHI"           # zwykłe komendy JSON
BIN_HEADER_FMT = "<BB2xIIBBHI"       # OPSNAP / binarne transfery: total(1B), cur(1B) zamiast paddingu
HEADER_LEN = struct.calcsize(HEADER_FMT)
assert struct.calcsize(BIN_HEADER_FMT) == HEADER_LEN

MSG_LOGIN_REQ = 1000
MSG_OPSNAP_REQ = 1560

JPEG_MAGICS = (0xFFD8FFE0, 0xFFD8FFDB)


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


def main():
    ap = argparse.ArgumentParser(description="Pobranie snapshotu JPEG przez DVRIP (OPSNAP)")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, default=3, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--out", default="snapshot.jpg")
    ap.add_argument("--timeout", type=float, default=10.0)
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
        text = payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace")
        return json.loads(text)

    # --- login ---
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

    # --- OPSNAP ---
    print(f"\n--- OPSNAP (kanał {args.channel}) ---")
    send(MSG_OPSNAP_REQ, {
        "Name": "OPSNAP",
        "SessionID": f"0x{session_id:08X}",
        "OPSNAP": {"Channel": args.channel},
    })

    sock.settimeout(args.timeout)
    jpeg = bytearray()
    chunk_i = 0
    while True:
        header_raw = read_exact(sock, HEADER_LEN)
        head, version, sess, seq, total, cur, msg_id, plen = struct.unpack(BIN_HEADER_FMT, header_raw)
        packet = read_exact(sock, plen) if plen else b""
        print(f"  [chunk {chunk_i}] head=0x{head:02X} version={version} total={total} "
              f"cur={cur} msg_id={msg_id} len={plen}")
        chunk_i += 1

        if chunk_i == 1:
            if len(packet) < 4:
                print("  Odpowiedź za krótka, brak danych JPEG.")
                sys.exit(1)
            data_type = struct.unpack(">I", packet[:4])[0]
            if data_type in JPEG_MAGICS:
                # cały packet TO już surowy JPEG (potwierdzone wzorcem community)
                jpeg.extend(packet)
                if total <= 1 or cur >= total - 1:
                    break
                continue
            else:
                print(f"  Nieoczekiwany typ danych: 0x{data_type:08X} (nie JPEG) — surowa odpowiedź:")
                print(f"    {packet[:80]!r}")
                sys.exit(1)
        else:
            jpeg.extend(packet)
            if cur >= total - 1:
                break

    print(f"\n=== Odebrano {len(jpeg)} bajtów JPEG w {chunk_i} chunkach ===")
    with open(args.out, "wb") as f:
        f.write(jpeg)
    print(f"Zapisano do {args.out}")
    print(f"Pierwsze bajty: {bytes(jpeg[:16]).hex()}")
    print(f"Ostatnie bajty: {bytes(jpeg[-4:]).hex()} (JPEG EOI = ffd9)")


if __name__ == "__main__":
    main()
