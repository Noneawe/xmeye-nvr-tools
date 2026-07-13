#!/usr/bin/env python3
"""
playback_download.py — pobranie nagrania (playback/download) z rejestratora XMEYE
przez DVRIP: wyszukanie plików (OPFileQuery, msg 1440) + pobranie konkretnego pliku
(OPPlayBack Claim/DownloadStart/DownloadStop, msg 1424/1420). Wzorzec z community
(python-dvr, metody list_local_files()/download_file()).

Nazwy plików mają tag `[R]` (regularne/ciągłe nagrywanie) albo `[M]` (nagranie
wyzwolone zdarzeniem/ruchem) — `[M]` to dokładnie to, czego szukamy dla "nagrania
z alarmu". BeginTime pliku `[M]` pokrywa się z timestampem realnego zdarzenia
AlarmInfo (potwierdzone: plik zaczynający się dokładnie w sekundzie, w której
`alarm_listen.py` złapał wcześniej push `FaceDetect`/`appEventHumanDetectAlarm`).

UWAGA — CIERPLIWOŚĆ: pobieranie nagrań na tym sprzęcie bywa BARDZO wolne, z rosnącymi
przerwami między fragmentami (potwierdzone: 18s, 4s, 17s, 3s, 11s, 38s, 22s, 74s...,
cały transfer >280s). To NIE jest błąd/zawieszenie — po prostu tak wolno chodzą te
DVR-y. Domyślny `--timeout` (budżet na nowe dane per chunk) jest ustawiony wysoko
(120s) właśnie z tego powodu — nie skracaj go zakładając, że coś jest zepsute.
Krótsze okno czasowe (`--begin`/`--end`, np. 5s zamiast pełnej długości pliku)
pomaga dostać choć kilka klatek szybciej, ale i tak wymaga cierpliwości.

Użycie:
    # 1. wyszukaj pliki w oknie czasowym:
    python3 playback_download.py search --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 --begin "2026-03-10 22:00:00" --end "2026-03-11 01:05:23"

    # 2. pobierz konkretny plik znaleziony w kroku 1 (najlepiej krótkie okno, patrz wyżej):
    python3 playback_download.py download --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 \
        --file "/idea0/2026-03-10/004/23.29.56-23.30.19[M][@5c99c][1].h264" \
        --begin "2026-03-10 23:29:56" --end "2026-03-10 23:30:01" --out alarm_clip.h264

    (channel liczone OD 0, jak OPMonitor/AlarmInfo — kanał fizyczny 4 = channel 3)
"""

import argparse
import hashlib
import json
import socket
import struct
import sys
import time

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_FILE_QUERY = 1440
MSG_PLAYBACK_CLAIM = 1424
MSG_PLAYBACK_CTRL = 1420  # Action: DownloadStart / DownloadStop


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


def read_exact(sock: socket.socket, n: int, overall_timeout: float = 15.0) -> bytes:
    """Odbiera dokładnie `n` bajtów, poll'ując krótkimi sub-timeoutami (5s) w ramach
    `overall_timeout`. Pobieranie nagrań na tym sprzęcie bywa BARDZO wolne (rosnące
    przerwy między chunkami rzędu kilkudziesięciu sekund, potwierdzone: transfer
    trwający >280s wciąż kończy się sukcesem) — krótki, sztywny timeout myli
    "wolno" z "zawieszone". Ustaw duży `overall_timeout` (rzędu minut) i czekaj."""
    data = b""
    sock.settimeout(5.0)
    t0 = time.time()
    while len(data) < n:
        try:
            chunk = sock.recv(n - len(data))
        except (socket.timeout, TimeoutError):
            if time.time() - t0 > overall_timeout:
                raise
            continue
        if not chunk:
            raise ConnectionError("połączenie zamknięte")
        data += chunk
        t0 = time.time()  # reset budżetu po każdym realnym postępie
    return data


class Client:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.session_id = 0
        self.sequence = 0

    def send(self, msg_id: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0x00, self.session_id, self.sequence, msg_id, len(body))
        self.sock.sendall(header + body)
        self.sequence += 1

    def recv_json(self) -> dict:
        header_raw = read_exact(self.sock, HEADER_LEN)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        payload_raw = read_exact(self.sock, plen) if plen else b""
        return json.loads(payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace"))

    def login(self, user: str, password: str) -> dict:
        self.send(MSG_LOGIN_REQ, {
            "EncryptType": "MD5", "LoginType": "DVRIP-Web",
            "PassWord": sofia_hash(password), "UserName": user,
        })
        data = self.recv_json()
        if data.get("Ret") not in (100, "100"):
            raise RuntimeError(f"login odrzucony: {data}")
        self.session_id = int(data["SessionID"], 16)
        return data


def cmd_search(args):
    client = Client(args.host, args.port, 10.0)
    client.login(args.user, args.password)
    client.send(MSG_FILE_QUERY, {
        "Name": "OPFileQuery",
        "SessionID": f"0x{client.session_id:08X}",
        "OPFileQuery": {
            "BeginTime": args.begin,
            "Channel": args.channel,
            "DriverTypeMask": "0x0000FFFF",
            "EndTime": args.end,
            "Event": "*",
            "StreamType": "0x00000000",
            "Type": "h264",
        },
    })
    resp = client.recv_json()
    files = resp.get("OPFileQuery", [])
    print(f"Znaleziono {len(files)} plików (kanał {args.channel}, {args.begin} .. {args.end}):\n")
    for f in files:
        tag = "[M]=zdarzenie" if "[M]" in (f.get("FileName") or "") else "[R]=ciągłe" if "[R]" in (f.get("FileName") or "") else ""
        print(f"  {f.get('BeginTime')} -> {f.get('EndTime')}  {tag}")
        print(f"    {f.get('FileName')}  (rozmiar={f.get('FileLength')})")


def cmd_download(args):
    client = Client(args.host, args.port, 10.0)
    client.login(args.user, args.password)

    playback_param = {
        "PlayMode": "ByName", "FileName": args.file,
        "StreamType": 0, "Value": 0, "TransMode": "TCP",
    }

    print("--- OPPlayBack Claim ---")
    client.send(MSG_PLAYBACK_CLAIM, {
        "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
        "OPPlayBack": {"Action": "Claim", "Parameter": playback_param,
                       "StartTime": args.begin, "EndTime": args.end},
    })
    claim_resp = client.recv_json()
    print(json.dumps(claim_resp, ensure_ascii=False))
    if claim_resp.get("Ret") not in (100, "100"):
        print("Claim nieudany, przerywam.")
        sys.exit(1)

    print("\n--- OPPlayBack DownloadStart ---")
    client.send(MSG_PLAYBACK_CTRL, {
        "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
        "OPPlayBack": {"Action": "DownloadStart", "Parameter": playback_param,
                       "StartTime": args.begin, "EndTime": args.end},
    })

    buf = bytearray()
    total = 0
    chunk_i = 0
    t_start = time.time()
    try:
        while True:
            header_raw = read_exact(client.sock, HEADER_LEN, overall_timeout=args.timeout)
            _, version, sess, seq, msg_id, plen = struct.unpack(HEADER_FMT, header_raw)
            if plen == 0:
                print(f"  (chunk {chunk_i}: len=0 -> koniec pliku)")
                break
            payload = read_exact(client.sock, plen, overall_timeout=args.timeout)
            buf.extend(payload)
            total += plen
            chunk_i += 1
            print(f"  [{time.time()-t_start:6.1f}s] chunk {chunk_i}: msg_id={msg_id} +{plen}B (razem={total}B)")
    except (socket.timeout, TimeoutError, ConnectionError) as e:
        print(f"  Przerwano po {chunk_i} chunkach ({total}B): {e}")
        print("  (to może być normalne — transfer na tym sprzęcie bywa bardzo wolny,")
        print("   spróbuj większego --timeout zamiast zakładać błąd)")

    print(f"\n--- OPPlayBack DownloadStop ---")
    client.send(MSG_PLAYBACK_CTRL, {
        "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
        "OPPlayBack": {"Action": "DownloadStop", "Parameter": {**playback_param, "Channel": args.channel},
                       "StartTime": args.begin, "EndTime": args.end},
    })
    try:
        print(client.recv_json())
    except Exception as e:
        print(f"(brak/nieoczekiwana odpowiedź na Stop — normalne, plik już zapisany: {e})")

    with open(args.out, "wb") as f:
        f.write(buf)
    print(f"\n=== Zapisano {len(buf)} bajtów do {args.out} ===")


def main():
    ap = argparse.ArgumentParser(description="Wyszukanie i pobranie nagrania z rejestratora XMEYE")
    sub = ap.add_subparsers(dest="cmd", required=True)

    common = dict(required=True)
    for name in ("search", "download"):
        p = sub.add_parser(name)
        p.add_argument("--host", required=True)
        p.add_argument("--user", required=True)
        p.add_argument("--password", required=True)
        p.add_argument("--port", type=int, default=34567)
        p.add_argument("--channel", type=int, default=3, help="0-based (kanał fizyczny 4 = 3)")
        p.add_argument("--begin", required=True, help='np. "2026-03-10 23:00:00"')
        p.add_argument("--end", required=True, help='np. "2026-03-11 01:05:23"')
        p.add_argument("--timeout", type=float, default=120.0,
                       help="budżet czasu (s) na dotarcie NOWYCH danych na chunk przy download — "
                            "transfer bywa bardzo wolny, nie skracaj bez potrzeby")
        if name == "download":
            p.add_argument("--file", required=True, help="FileName z wyniku search")
            p.add_argument("--out", default="playback.h264")

    args = ap.parse_args()
    if args.cmd == "search":
        cmd_search(args)
    else:
        cmd_download(args)


if __name__ == "__main__":
    main()
