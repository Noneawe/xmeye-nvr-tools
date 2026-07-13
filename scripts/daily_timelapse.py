#!/usr/bin/env python3
"""
daily_timelapse.py — pobierz z rejestratora XMEYE jedną klatkę (JPEG) co minutę
dla wskazanego kanału, dla całej doby (00:00 - 23:59), z nagrań (nie z live).

WAŻNE — REALIZM CZASOWY: pojedyncza klatka z playbacku, przy pełnej rozdzielczości
nagrania, potrafi zająć od kilkunastu sekund do KILKUNASTU MINUT (potwierdzone w
Fazie 3, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo — duże transfery binarne na tym sprzęcie bywają bardzo
niestabilne/wolne). 1440 klatek (doba) tą metodą to potencjalnie WIELE GODZIN.
Skrypt jest zaprojektowany do długiego, przerywalnego działania:
  - pomija minuty, dla których plik JPEG już istnieje (można bezpiecznie przerwać
    i wznowić tym samym poleceniem)
  - błąd pojedynczej minuty (timeout, brak nagrania, uszkodzona ramka) NIE
    przerywa całego biegu — loguje i idzie dalej
  - loguje postęp na bieżąco (ile minut zrobione, ile pominięte, szacowany czas)

Jak to działa:
  1. `OPFileQuery` (z paginacją — max 64 wyników/zapytanie, potwierdzone w
     community python-dvr) pobiera listę WSZYSTKICH nagranych segmentów dla
     kanału i doby.
  2. Dla każdej docelowej minuty (00:00, 00:01, ..., 23:59) znajdź segment,
     który ją obejmuje. Brak segmentu = brak nagrania w tej minucie = pomiń
     (to normalne, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo — kanały bywają offline/bez ruchu).
  3. Start playbacku MUSI być dokładnie od `BeginTime` samego segmentu (nie
     dowolny moment w środku!) — potwierdzone w Fazie 3: playback od momentu
     w środku pliku zwraca uszkodzone ramki. Dlatego zapisana klatka to
     pierwsza dostępna klatka danego segmentu (blisko docelowej minuty, nie
     zawsze idealnie co do sekundy).
  4. Złap pierwszą kompletną klatkę I-frame, zdekoduj (PyAV), zapisz JPEG.

Zależności (jak snapshot_from_opmonitor.py/alarm_photos.py): `pip install av pillow`.

Użycie:
    python3 daily_timelapse.py --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 --date 2026-03-10 \
        --out-dir /sciezka/do/folderu
    (channel liczone OD 0, jak OPMonitor/AlarmInfo/OPFileQuery — kanał fizyczny 4 = 3)

    Test na małym wycinku doby (zalecane przed pełnym biegiem):
    python3 daily_timelapse.py ... --start 14:00 --end 14:05
"""

import argparse
import datetime
import hashlib
import io
import json
import os
import shutil
import socket
import struct
import sys
import time

try:
    import av
except ImportError:
    print("Brakuje pakietu 'av' (PyAV). Zainstaluj: pip install av pillow")
    sys.exit(1)

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_FILE_QUERY = 1440
MSG_PLAYBACK_CLAIM = 1424
MSG_PLAYBACK_CTRL = 1420  # Action: DownloadStart / DownloadStop

DATE_FMT = "%Y-%m-%d %H:%M:%S"


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


def read_exact(sock: socket.socket, n: int, overall_timeout: float) -> bytes:
    """Poll'uje krótkimi sub-timeoutami (5s), resetując budżet przy każdym realnym
    postępie — patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, transfery playbacku bywają BARDZO wolne."""
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


class Client:
    def __init__(self, host: str, port: int, timeout: float = 15.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.session_id = 0
        self.sequence = 0

    def send(self, msg_id: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8") + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0x00, self.session_id, self.sequence, msg_id, len(body))
        self.sock.sendall(header + body)
        self.sequence += 1

    def recv_json(self, timeout: float = 15.0) -> dict:
        header_raw = read_exact(self.sock, HEADER_LEN, timeout)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, header_raw)
        payload_raw = read_exact(self.sock, plen, timeout) if plen else b""
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

    def close(self) -> None:
        self.sock.close()


def query_day_files(host: str, port: int, user: str, password: str, channel: int,
                     day_start: str, day_end: str) -> list[dict]:
    """OPFileQuery z paginacją (max 64 wyników/zapytanie, community python-dvr)."""
    client = Client(host, port)
    client.login(user, password)

    results: list[dict] = []
    begin_time = day_start
    seen_keys = set()

    while True:
        # Ten sam sprzęt bywa niestabilny przy dłuższych sesjach (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo,
        # Faza 3) — ponawiaj pojedynczą stronę zapytania zamiast wywalać cały bieg.
        resp = None
        for attempt in range(5):
            try:
                client.send(MSG_FILE_QUERY, {
                    "Name": "OPFileQuery",
                    "SessionID": f"0x{client.session_id:08X}",
                    "OPFileQuery": {
                        "BeginTime": begin_time,
                        "Channel": channel,
                        "DriverTypeMask": "0x0000FFFF",
                        "EndTime": day_end,
                        "Event": "*",
                        "StreamType": "0x00000000",
                        "Type": "h264",
                    },
                })
                resp = client.recv_json(timeout=20)
                break
            except (socket.timeout, TimeoutError, ConnectionError, OSError) as e:
                print(f"  (wyszukiwanie plików: błąd '{e}', próba {attempt+1}/5, "
                      f"nowe połączenie...)")
                client.close()
                time.sleep(3)
                client = Client(host, port)
                client.login(user, password)
        if resp is None:
            print("  (wyszukiwanie plików: 5 nieudanych prób, przerywam paginację)")
            break
        if resp.get("Ret") not in (100, "100"):
            break
        batch = resp.get("OPFileQuery", [])
        new_in_batch = 0
        for f in batch:
            key = (f.get("BeginTime"), f.get("FileName"))
            if key not in seen_keys:
                seen_keys.add(key)
                results.append(f)
                new_in_batch += 1
        if len(batch) < 64 or new_in_batch == 0:
            break
        # paginacja: kolejne zapytanie zaczyna od BeginTime ostatniego wyniku
        begin_time = batch[-1]["BeginTime"]

    client.close()
    results.sort(key=lambda f: f["BeginTime"])
    return results


def read_dvrip_chunk(sock: socket.socket, timeout: float) -> bytes:
    header = read_exact(sock, HEADER_LEN, timeout)
    if header[0] != 0xFF:
        raise ValueError(f"zły head w chunku: {header[:20]!r}")
    _, _, _, _, _, size = struct.unpack(HEADER_FMT, header)
    if size == 0:
        return b""
    return read_exact(sock, size, timeout)


def grab_first_iframe(host: str, port: int, user: str, password: str,
                       channel: int, filename: str, begin_time: str, end_time: str,
                       timeout: float) -> bytes:
    """Nowa sesja OPPlayBack od `begin_time` (MUSI być BeginTime samego pliku —
    patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, Faza 3), zwraca bajty Annex-B pierwszej kompletnej klatki I."""
    client = Client(host, port)
    try:
        client.login(user, password)
        param = {"PlayMode": "ByName", "FileName": filename,
                 "StreamType": 0, "Value": 0, "TransMode": "TCP"}

        client.send(MSG_PLAYBACK_CLAIM, {
            "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
            "OPPlayBack": {"Action": "Claim", "Parameter": param,
                           "StartTime": begin_time, "EndTime": end_time},
        })
        claim_resp = client.recv_json(timeout=15)
        if claim_resp.get("Ret") not in (100, "100"):
            raise RuntimeError(f"Claim nieudany: {claim_resp}")

        client.send(MSG_PLAYBACK_CTRL, {
            "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
            "OPPlayBack": {"Action": "DownloadStart", "Parameter": param,
                           "StartTime": begin_time, "EndTime": end_time},
        })

        buf = bytearray()
        while len(buf) < 16:
            buf.extend(read_dvrip_chunk(client.sock, timeout))
        if bytes(buf[:3]) != b"\x00\x00\x01":
            raise ValueError(f"zły prefiks ramki A/V: {bytes(buf[:16])!r}")
        ptype = buf[3]
        if ptype not in (0xFC, 0xFE):
            raise ValueError(f"pierwsza ramka nie jest I-frame (typ=0x{ptype:02X})")
        size = struct.unpack_from("<I", buf, 12)[0] + 16
        while len(buf) < size:
            buf.extend(read_dvrip_chunk(client.sock, timeout))
        payload = bytes(buf[:size])
        return payload[16:]  # Annex-B: VPS+SPS+PPS+IDR
    finally:
        try:
            client.send(MSG_PLAYBACK_CTRL, {
                "Name": "OPPlayBack", "SessionID": f"0x{client.session_id:08X}",
                "OPPlayBack": {"Action": "DownloadStop",
                               "Parameter": {"FileName": filename, "PlayMode": "ByName",
                                             "StreamType": 0, "TransMode": "TCP",
                                             "Channel": channel, "Value": 0},
                               "StartTime": begin_time, "EndTime": end_time},
            })
        except OSError:
            pass
        client.close()


def find_segment(files: list[dict], target: datetime.datetime) -> dict | None:
    """Segment, którego [BeginTime, EndTime) obejmuje `target`. None = brak
    nagrania w tej minucie (normalne, patrz docstring modułu)."""
    for f in files:
        try:
            begin = datetime.datetime.strptime(f["BeginTime"], DATE_FMT)
            end = datetime.datetime.strptime(f["EndTime"], DATE_FMT)
        except (KeyError, ValueError):
            continue
        if begin <= target < end:
            return f
    return None


def main():
    ap = argparse.ArgumentParser(description="Klatka co minutę z nagrań XMEYE dla całej doby")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, required=True, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--date", required=True, help="YYYY-MM-DD")
    ap.add_argument("--out-dir", required=True)
    ap.add_argument("--start", default="00:00", help="HH:MM, domyślnie 00:00 (początek doby)")
    ap.add_argument("--end", default="23:59", help="HH:MM, domyślnie 23:59 (koniec doby)")
    ap.add_argument("--timeout", type=float, default=180.0,
                     help="budżet cierpliwości per klatka (s) — patrz ostrzeżenie w docstringu")
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    start_dt = datetime.datetime.strptime(f"{args.date} {args.start}", "%Y-%m-%d %H:%M")
    end_dt = datetime.datetime.strptime(f"{args.date} {args.end}", "%Y-%m-%d %H:%M")

    # Szukaj tylko w faktycznie potrzebnym oknie (+/- 1 min na granice segmentów),
    # nie zawsze całej doby — szybsze i mniej podatne na niestabilność sprzętu
    # przy testach na krótkim wycinku.
    query_start = (start_dt - datetime.timedelta(minutes=1)).strftime(DATE_FMT)
    query_end = (end_dt + datetime.timedelta(minutes=1)).strftime(DATE_FMT)

    print(f"Szukam nagrań: kanał {args.channel}, {query_start} .. {query_end}...")
    files = query_day_files(args.host, args.port, args.user, args.password,
                             args.channel, query_start, query_end)
    print(f"Znaleziono {len(files)} segmentów nagrań w tym oknie.\n")

    minutes = []
    cur = start_dt
    while cur <= end_dt:
        minutes.append(cur)
        cur += datetime.timedelta(minutes=1)

    print(f"Cel: {len(minutes)} klatek ({args.start} - {args.end}), zapis do {args.out_dir}\n")

    done = 0
    reused = 0
    skipped_existing = 0
    skipped_no_segment = 0
    failed = 0
    t_run_start = time.time()
    # Segmenty ciągłe ("[R]") potrafią trwać kilkanaście minut - kilka kolejnych
    # docelowych minut często trafia w TEN SAM segment. Zamiast pobierać tę samą
    # (identyczną) pierwszą klatkę wielokrotnie, cache'uj po nazwie pliku segmentu
    # i przy trafieniu po prostu skopiuj już zapisany JPEG - bez sieci.
    segment_cache: dict[str, str] = {}

    for i, minute_dt in enumerate(minutes):
        hhmm = minute_dt.strftime("%H:%M")
        out_path = os.path.join(args.out_dir, f"{args.channel}_{args.date}_{hhmm}.jpg")

        if os.path.exists(out_path):
            skipped_existing += 1
            continue

        segment = find_segment(files, minute_dt)
        if segment is None:
            print(f"[{i+1}/{len(minutes)}] {hhmm}: brak nagrania w tej minucie, pomijam")
            skipped_no_segment += 1
            continue

        cached_path = segment_cache.get(segment["FileName"])
        if cached_path is not None:
            shutil.copy2(cached_path, out_path)
            reused += 1
            print(f"[{i+1}/{len(minutes)}] {hhmm}: OK (0.0s, z cache — ten sam segment co poprzednio)")
            continue

        t0 = time.time()
        try:
            h265_data = grab_first_iframe(
                args.host, args.port, args.user, args.password, args.channel,
                segment["FileName"], segment["BeginTime"], segment["EndTime"], args.timeout,
            )
            container = av.open(io.BytesIO(h265_data), format="hevc")
            frame = next(container.decode(video=0))
            frame.to_image().save(out_path, quality=90)
            segment_cache[segment["FileName"]] = out_path
            elapsed = time.time() - t0
            done += 1
            avg = (time.time() - t_run_start) / max(done, 1)
            remaining = len(minutes) - i - 1
            eta_min = (remaining * avg) / 60
            print(f"[{i+1}/{len(minutes)}] {hhmm}: OK ({elapsed:.1f}s, {frame.width}x{frame.height}) "
                  f"— zrobione={done} (+{reused} z cache) pominięte={skipped_no_segment+skipped_existing} "
                  f"błędy={failed} — szac. pozostały czas: {eta_min:.0f} min")
        except Exception as e:
            failed += 1
            print(f"[{i+1}/{len(minutes)}] {hhmm}: BŁĄD ({time.time()-t0:.1f}s): {e}")

    total_time = time.time() - t_run_start
    print(f"\n=== KONIEC ===")
    print(f"Pobrane z sieci: {done}, z cache (ten sam segment): {reused}, "
          f"pominięte (już istniały): {skipped_existing}, "
          f"pominięte (brak nagrania): {skipped_no_segment}, błędy: {failed}")
    print(f"Czas: {total_time/60:.1f} min")


if __name__ == "__main__":
    main()
