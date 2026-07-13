#!/usr/bin/env python3
"""
alarm_photos.py — N zdjęć (JPEG) z zapisanego nagrania alarmowego, rozstawionych
co `--interval` sekund od momentu wystąpienia.

WAŻNE — podejście "osobna sesja OPPlayBack per zdjęcie od innej sekundy" NIE
działa niezawodnie na tym sprzęcie: żądanie startu playbacku od dowolnego momentu
W ŚRODKU pliku (nie od jego naturalnego początku) potrafi zwrócić dane, które nie
zaczynają się czystą ramką A/V (błąd "zły prefiks ramki") — sprawdzone empirycznie,
3/3 próby nieudane. Zamiast tego ten skrypt robi JEDEN ciągły odbiór od początku
pliku (to działa niezawodnie, tylko wolno — patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo) i wybiera z niego
klatki po indeksie, na podstawie realnego frameratu nagrania (odczytanego z
nagłówka pierwszej klatki I — bajt `fps` w formacie z go2rtc/`opmonitor_probe.py`).
Potwierdzone na żywo: nagranie 4K na tym sprzęcie ma **10 fps**, więc np. żeby
dostać zdjęcia co 1s potrzeba klatek o indeksach 0, 10, 20, ...

UWAGA — CIERPLIWOŚĆ: pełny odbiór ~3.5s materiału (36 klatek, potrzebne do zdjęć
w interwałach do +2s) zajął **~920 sekund (~15 minut)** przy 4K. To NIE jest
błąd — duże ciągłe transfery na tym sprzęcie są po prostu bardzo wolne, ale kończą
się sukcesem. Uruchamiaj to w tle, z dużym `--max-seconds` (rzędu 900-1800).

Zależności (jak `snapshot_from_opmonitor.py`): `pip install av pillow`.

Użycie:
    python3 alarm_photos.py --host 192.168.1.100 --user tester --password 'HASLO!' \
        --channel 3 --file "/idea0/2026-03-10/004/23.29.56-23.30.19[M][@5c99c][1].h264" \
        --begin "2026-03-10 23:29:56" --end "2026-03-10 23:30:19" \
        --count 3 --interval 1 --max-seconds 1200 --out-prefix alarm
    (channel liczone OD 0, jak OPMonitor/AlarmInfo — kanał fizyczny 4 = channel 3)
"""

import argparse
import io
import json
import os
import socket
import struct
import sys
import time
from collections import Counter

try:
    import av
except ImportError:
    print("Brakuje pakietu 'av' (PyAV). Zainstaluj: pip install av pillow")
    sys.exit(1)

import hashlib

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_PLAYBACK_CLAIM = 1424
MSG_PLAYBACK_CTRL = 1420


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


def read_exact(sock: socket.socket, n: int, overall_timeout: float) -> bytes:
    """Poll'uje krótkimi sub-timeoutami (5s), resetując budżet przy każdym realnym
    postępie — patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, transfery playbacku bywają BARDZO wolne (przerwy
    między chunkami rzędu dziesiątek-set sekund), ale kończą się sukcesem."""
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
        t0 = time.time()
    return data


def download_playback(host, port, user, password, filename, begin, end, max_seconds, chunk_timeout):
    """Ciągły odbiór surowych chunków DVRIP od początku pliku, aż do `max_seconds`
    łącznego budżetu albo naturalnego końca (chunk z payload_len=0)."""
    sock = socket.create_connection((host, port), timeout=15)
    session_id = 0
    sequence = 0

    def send(msg_id: int, payload: dict) -> None:
        nonlocal sequence
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0x00, session_id, sequence, msg_id, len(body))
        sock.sendall(header + body)
        sequence += 1

    def recv_json() -> dict:
        header_raw = read_exact(sock, HEADER_LEN, overall_timeout=15)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        payload_raw = read_exact(sock, plen, overall_timeout=15) if plen else b""
        return json.loads(payload_raw.rstrip(b"\x00\x0a").decode("utf-8", errors="replace"))

    send(MSG_LOGIN_REQ, {
        "EncryptType": "MD5", "LoginType": "DVRIP-Web",
        "PassWord": sofia_hash(password), "UserName": user,
    })
    login_data = recv_json()
    if login_data.get("Ret") not in (100, "100"):
        raise RuntimeError(f"login odrzucony: {login_data}")
    session_id = int(login_data["SessionID"], 16)
    print(f"Zalogowano, SessionID=0x{session_id:08X}")

    param = {"PlayMode": "ByName", "FileName": filename,
             "StreamType": 0, "Value": 0, "TransMode": "TCP"}

    send(MSG_PLAYBACK_CLAIM, {
        "Name": "OPPlayBack", "SessionID": f"0x{session_id:08X}",
        "OPPlayBack": {"Action": "Claim", "Parameter": param, "StartTime": begin, "EndTime": end},
    })
    claim_resp = recv_json()
    print("Claim:", claim_resp)
    if claim_resp.get("Ret") not in (100, "100"):
        raise RuntimeError(f"Claim nieudany: {claim_resp}")

    send(MSG_PLAYBACK_CTRL, {
        "Name": "OPPlayBack", "SessionID": f"0x{session_id:08X}",
        "OPPlayBack": {"Action": "DownloadStart", "Parameter": param, "StartTime": begin, "EndTime": end},
    })

    buf = bytearray()
    total = 0
    t_start = time.time()
    while time.time() - t_start < max_seconds:
        try:
            header_raw = read_exact(sock, HEADER_LEN, overall_timeout=chunk_timeout)
        except (socket.timeout, TimeoutError):
            print(f"[{time.time()-t_start:.1f}s] timeout czekając na nagłówek, kończę z {total}B")
            break
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        if plen == 0:
            print(f"[{time.time()-t_start:.1f}s] koniec pliku (chunk pusty), total={total}B")
            break
        try:
            payload = read_exact(sock, plen, overall_timeout=chunk_timeout)
        except (socket.timeout, TimeoutError):
            print(f"[{time.time()-t_start:.1f}s] timeout w trakcie chunku, kończę z {total}B")
            break
        buf.extend(payload)
        total += len(payload)
        print(f"[{time.time()-t_start:6.1f}s] +{len(payload)}B total={total}B")

    try:
        send(MSG_PLAYBACK_CTRL, {
            "Name": "OPPlayBack", "SessionID": f"0x{session_id:08X}",
            "OPPlayBack": {"Action": "DownloadStop", "Parameter": {**param, "Channel": 0},
                           "StartTime": begin, "EndTime": end},
        })
    except OSError:
        pass
    sock.close()
    return bytes(buf)


def extract_video_frames(raw: bytes) -> tuple[list[bytes], int | None]:
    """Parsuje surowe chunki na ramki A/V (prefiks 00 00 01 + typ + rozmiar,
    format z go2rtc), zwraca (payloady I/P-klatek bez audio, framerate z nagłówka
    pierwszej I-klatki — bajt offset 5, jak w producer.go/go2rtc). Framerate
    RÓŻNI SIĘ per kanał/profil nagrywania (potwierdzone: kanał 4 ma 10fps, kanał 5
    dużo więcej) — nie zgaduj, czytaj z nagłówka."""
    buf = bytearray(raw)
    frames = []
    detected_fps = None
    while len(buf) >= 16:
        if bytes(buf[:3]) != b"\x00\x00\x01":
            break
        ptype = buf[3]
        if ptype in (0xFC, 0xFE):
            if detected_fps is None:
                detected_fps = buf[5]
            size = struct.unpack_from("<I", buf, 12)[0] + 16
            hlen = 16
        elif ptype == 0xFD:
            size = struct.unpack_from("<I", buf, 4)[0] + 8
            hlen = 8
        elif ptype in (0xFA, 0xF9):
            size = struct.unpack_from("<H", buf, 6)[0] + 8
            hlen = 8
        else:
            break
        if size > len(buf):
            break
        if ptype in (0xFC, 0xFE, 0xFD):
            frames.append((ptype, bytes(buf[hlen:size])))
        del buf[:size]
    print(f"Znaleziono {len(frames)} kompletnych ramek wideo:", Counter(hex(t) for t, _ in frames))
    print(f"Framerate z nagłówka I-klatki: {detected_fps} fps")
    return [p for _, p in frames], detected_fps


def main():
    ap = argparse.ArgumentParser(description="N zdjęć z nagrania alarmowego, co interval sekund")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, required=True, help="0-based, tylko do logów")
    ap.add_argument("--file", required=True, help="FileName z playback_download.py search")
    ap.add_argument("--begin", required=True, help="BeginTime pliku, np. \"2026-03-10 23:29:56\"")
    ap.add_argument("--end", required=True, help="EndTime pliku")
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--interval", type=float, default=1.0, help="odstęp w sekundach")
    ap.add_argument("--max-seconds", type=float, default=1200.0,
                     help="łączny budżet czasu na cały odbiór (transfer bywa bardzo wolny)")
    ap.add_argument("--chunk-timeout", type=float, default=150.0)
    ap.add_argument("--out-prefix", default="alarm_photo")
    ap.add_argument("--cache-file",
                     help="jeśli podane i plik istnieje: wczytaj surowe dane stamtąd "
                          "zamiast pobierać ponownie (pobieranie potrafi trwać kilkanaście "
                          "minut — nie trać go, jeśli tylko trzeba poprawić dobór klatek); "
                          "jeśli podane i plik NIE istnieje: pobierz i tam zapisz")
    ap.add_argument("--fps", type=int, help="wymuś framerate zamiast auto-wykrywania z nagłówka")
    args = ap.parse_args()

    if args.cache_file and os.path.exists(args.cache_file):
        print(f"Wczytuję surowe dane z cache: {args.cache_file}")
        with open(args.cache_file, "rb") as f:
            raw = f.read()
    else:
        raw = download_playback(
            args.host, args.port, args.user, args.password,
            args.file, args.begin, args.end, args.max_seconds, args.chunk_timeout,
        )
        print(f"\nRazem odebrano {len(raw)} bajtów.")
        if args.cache_file:
            with open(args.cache_file, "wb") as f:
                f.write(raw)
            print(f"Zapisano surowe dane do cache: {args.cache_file}")

    video_payloads, detected_fps = extract_video_frames(raw)
    if not video_payloads:
        print("Brak kompletnych ramek wideo — nic do zdekodowania.")
        sys.exit(1)

    elementary = b"".join(video_payloads)
    container = av.open(io.BytesIO(elementary), format="hevc")
    frames = list(container.decode(video=0))
    print(f"Zdekodowano {len(frames)} klatek.")
    if not frames:
        print("PyAV nie zdekodował żadnej klatki.")
        sys.exit(1)

    fps = args.fps or detected_fps
    if not fps:
        print("Nie udało się ustalić fps (ani z nagłówka, ani --fps) — przyjmuję 10.")
        fps = 10

    needed = int(round((args.count - 1) * args.interval * fps)) + 1
    if len(frames) < needed:
        print(f"UWAGA: pobrano tylko {len(frames)} klatek, a potrzeba ~{needed} "
              f"(przy {fps} fps) żeby pokryć {args.count} zdjęć co {args.interval}s. "
              f"Zapisuję tyle, ile się da.")

    for i in range(args.count):
        idx = min(int(round(i * args.interval * fps)), len(frames) - 1)
        frame = frames[idx]
        out_path = f"{args.out_prefix}_{i + 1}_t{idx / fps:.1f}s.jpg"
        frame.to_image().save(out_path, quality=90)
        print(f"Zapisano {out_path} (klatka {idx}/{len(frames)-1}, ~t={idx/fps:.1f}s, {frame.width}x{frame.height})")


if __name__ == "__main__":
    main()
