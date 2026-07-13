#!/usr/bin/env python3
"""
periodic_snapshots.py — pobierz z rejestratora XMEYE jedną klatkę (JPEG) co
zadany krok czasowy (np. co 1min, co 30sec) dla wskazanego kanału i dnia,
z nagrań archiwalnych (nie z live). Ogólniejsza wersja daily_timelapse.py
(tam krok był na sztywno 1 minuta) — ta sama, sprawdzona logika (OPFileQuery +
OPPlayBack), tylko z konfigurowalnym krokiem i opcjonalnym oknem godzin.

WAŻNE — REALIZM CZASOWY: pojedyncza klatka z playbacku, przy pełnej rozdzielczości
nagrania, potrafi zająć od kilkunastu sekund do KILKUNASTU MINUT (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo —
duże transfery binarne na tym sprzęcie bywają bardzo niestabilne/wolne, choć po
naprawie sieci przez użytkownika zwykle jest to sekundy, nie minuty). Krótki krok
(np. 15sec) na długi zakres godzin może dać BARDZO dużo klatek do pobrania — użyj
--start/--end, żeby ograniczyć zakres, jeśli nie potrzebujesz całej doby.

Skrypt jest zaprojektowany do długiego, przerywalnego działania:
  - pomija momenty, dla których plik JPEG już istnieje (można bezpiecznie przerwać
    i wznowić tym samym poleceniem)
  - błąd pojedynczego segmentu (timeout, zerwane połączenie — do 2 prób) NIE
    przerywa całego biegu — loguje i idzie dalej z pozostałymi segmentami
  - grupuje cele po segmencie nagrania i robi JEDEN ciągły odbiór na grupę,
    pokrywający najdalej potrzebne przesunięcie czasowe w tym segmencie —
    KAŻDY cel dostaje właściwą, różną klatkę (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo: wcześniejsza
    wersja myliła "ten sam segment" z "ta sama klatka" i kopiowała identyczne
    zdjęcie do wszystkich celów w długim segmencie [R] — realny bug, znaleziony
    przy teście z krokiem 1min na 15-minutowym oknie)
  - dekoduje strumieniowo (nie ładuje wszystkich klatek długiego segmentu do
    RAM naraz — dla ~900s przy 1080p to potrafi być dziesiątki GB)
  - loguje postęp na bieżąco (ile zrobione, ile pominięte, szacowany czas)

Jak to działa (identycznie jak daily_timelapse.py, plus grupowanie po segmencie):
  1. `OPFileQuery` (z paginacją, max 64 wyników/zapytanie) pobiera listę segmentów
     nagrań dla kanału i żądanego okna czasu.
  2. Dla każdego docelowego momentu znajdź segment, który go obejmuje. Brak
     segmentu = brak nagrania w tym momencie = pomiń (normalne, kanały bywają
     offline/bez ruchu). Cele trafiające w ten sam segment idą do jednej grupy.
  3. Start playbacku MUSI być dokładnie od `BeginTime` samego segmentu (nie
     dowolny moment w środku!) — potwierdzone w Fazie 3. Dla każdej grupy: JEDEN
     ciągły odbiór od `BeginTime`, zatrzymany wcześnie po zebraniu tylu klatek,
     ile trzeba żeby pokryć najdalszy cel grupy.
  4. Zdekoduj strumieniowo (PyAV, próba HEVC → H.264 — kodek archiwum różni się
     między urządzeniami, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo) i zapisz klatkę o właściwym indeksie
     (przesunięcie_sekundy × fps) dla każdego celu w grupie jako JPEG.

Zależności: `pip install av pillow`.

Użycie:
    python3 periodic_snapshots.py --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 --date 2026-07-03 --step 1min \
        --out-dir /sciezka/do/folderu
    (channel liczone OD 0, jak OPMonitor/AlarmInfo/OPFileQuery — kanał fizyczny 4 = 3)

    Krok co 30 sekund, tylko okno 07:00-07:10:
    python3 periodic_snapshots.py ... --step 30sec --start 07:00 --end 07:10

    Dopuszczalne wartości --step (zamknięty zestaw, patrz STEP_CHOICES):
    "2min", "1min", "30sec", "15sec", "10sec", "5sec".
"""

import argparse
import datetime
import hashlib
import io
import itertools
import json
import os
import re
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
STEP_RE = re.compile(r"^(\d+)\s*(min|sec)$", re.IGNORECASE)
# Zamknięty zestaw dopuszczalnych kroków (walidowany przez argparse `choices`,
# widoczny w --help) — `parse_step()` sam w sobie obsłużyłby dowolną liczbę +
# 'min'/'sec', ale ograniczamy CLI do tego, co realnie ma sens dla snapshotów
# archiwalnych (krótszy krok niż 5sec generuje nieproporcjonalnie dużo żądań
# OPPlayBack względem tego, ile realnie różni się obraz między klatkami).
STEP_CHOICES = ["2min", "1min", "30sec", "15sec", "10sec", "5sec"]


def parse_step(step_str: str) -> datetime.timedelta:
    """Sparsuj krok w formacie '<liczba><min|sec>', np. '1min', '30sec'."""
    m = STEP_RE.match(step_str.strip())
    if not m:
        raise argparse.ArgumentTypeError(
            f"Nieprawidłowy --step: {step_str!r} — użyj liczby z sufiksem "
            f"'min' albo 'sec', np. '1min', '30sec', '5min', '15sec'."
        )
    value = int(m.group(1))
    if value <= 0:
        raise argparse.ArgumentTypeError("--step musi być dodatnią liczbą")
    unit = m.group(2).lower()
    if unit == "min":
        return datetime.timedelta(minutes=value)
    return datetime.timedelta(seconds=value)


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


def read_exact(sock: socket.socket, n: int, overall_timeout: float) -> bytes:
    """Poll'uje krótkimi sub-timeoutami (5s), resetując budżet przy każdym realnym
    postępie — patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, transfery playbacku bywają bardzo wolne."""
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


def query_range_files(host: str, port: int, user: str, password: str, channel: int,
                       range_start: str, range_end: str) -> list[dict]:
    """OPFileQuery z paginacją (max 64 wyników/zapytanie, community python-dvr)."""
    client = Client(host, port)
    client.login(user, password)

    results: list[dict] = []
    begin_time = range_start
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
                        "EndTime": range_end,
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


def extract_video_frames(raw: bytes) -> tuple[list[bytes], int | None]:
    """Parsuje surowe chunki na ramki A/V (prefiks 00 00 01 + typ + rozmiar,
    format z go2rtc), zwraca (payloady I/P-klatek bez audio, framerate z nagłówka
    pierwszej I-klatki — bajt offset 5). Framerate RÓŻNI SIĘ per kanał/urządzenie —
    nie zgaduj, czytaj z nagłówka (patrz alarm_photos.py, ten sam mechanizm)."""
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
    return [p for _, p in frames], detected_fps


def grab_segment_frames(host: str, port: int, user: str, password: str,
                         channel: int, filename: str, begin_time: str, end_time: str,
                         max_offset_seconds: float, timeout: float) -> tuple[bytes, int]:
    """Nowa sesja OPPlayBack od `begin_time` (MUSI być BeginTime samego pliku —
    patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, Faza 3) — JEDEN ciągły odbiór (nie osobna sesja per klatka,
    bo start playbacku w środku pliku nie działa niezawodnie, patrz
    alarm_photos.py), zatrzymany wcześnie, jak tylko zebrano wystarczająco klatek
    wideo żeby pokryć `max_offset_seconds` od początku segmentu (zamiast zawsze
    ciągnąć cały, potencjalnie wielominutowy segment). Zwraca (surowe bajty do
    sparsowania przez `extract_video_frames`, fps z nagłówka pierwszej I-klatki)."""
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

        raw = bytearray()
        pos = 0  # granica ostatniej KOMPLETNEJ sparsowanej ramki w `raw`
        video_frame_count = 0
        fps = None
        needed_frames = None
        while True:
            # Długie, ciągłe sesje OPPlayBack na tym sprzęcie bywają niestabilne
            # (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, Faza 3) — połączenie potrafi zostać zerwane w
            # środku transferu. Zamiast wywalać cały bieg, kończ odbiór z tym,
            # co już zebrano (dalej może wystarczyć na część celów w tej grupie
            # — patrz clamp przy przydzielaniu klatek w main()).
            try:
                chunk = read_dvrip_chunk(client.sock, timeout)
            except (socket.timeout, TimeoutError, ConnectionError, OSError) as e:
                print(f"  (przerwane połączenie w trakcie odbioru: {e} — "
                      f"kończę z tym, co już zebrano: {video_frame_count} klatek)")
                break
            if not chunk:
                break  # naturalny koniec segmentu
            raw.extend(chunk)

            # Parsuj tylko NOWO dostępne, kompletne ramki (bez re-parsowania od
            # zera przy każdym chunku — ważne przy potencjalnie dużych, wielo-
            # minutowych segmentach).
            while len(raw) - pos >= 16:
                if bytes(raw[pos:pos + 3]) != b"\x00\x00\x01":
                    break  # desync — przestań parsować, ale odbieraj dalej
                ptype = raw[pos + 3]
                if ptype in (0xFC, 0xFE):
                    if fps is None:
                        fps = raw[pos + 5] or 10
                        needed_frames = int(max_offset_seconds * fps) + 2
                    size = struct.unpack_from("<I", raw, pos + 12)[0] + 16
                elif ptype == 0xFD:
                    size = struct.unpack_from("<I", raw, pos + 4)[0] + 8
                elif ptype in (0xFA, 0xF9):
                    size = struct.unpack_from("<H", raw, pos + 6)[0] + 8
                else:
                    break
                if pos + size > len(raw):
                    break  # ramka jeszcze niekompletna
                if ptype in (0xFC, 0xFE, 0xFD):
                    video_frame_count += 1
                pos += size

            if needed_frames is not None and video_frame_count >= needed_frames:
                break

        return bytes(raw[:pos]), (fps or 10)
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
    nagrania w tym momencie (normalne, patrz docstring modułu)."""
    for f in files:
        try:
            begin = datetime.datetime.strptime(f["BeginTime"], DATE_FMT)
            end = datetime.datetime.strptime(f["EndTime"], DATE_FMT)
        except (KeyError, ValueError):
            continue
        if begin <= target < end:
            return f
    return None


def fetch_segment_targets(host: str, port: int, user: str, password: str, channel: int,
                           segment: dict, items: list[tuple[str, datetime.datetime, str]],
                           timeout: float, retries: int = 2) -> tuple[int, int]:
    """Pobierz i zapisz zdjęcia dla WSZYSTKICH `items` trafiających w JEDEN
    segment nagrania (JEDEN ciągły odbiór, nie osobna sesja per zdjęcie —
    patrz `grab_segment_frames`). `items`: lista (label, target_dt, out_path)
    — `label` tylko do logów (np. "3/16 07:02:00" albo "alarm#2 +5s"). Zwraca
    (liczba_zapisanych, liczba_błędów). Współdzielone między `main()` tego
    skryptu i `alarm_snapshots.py` — cała logika dekodowania (grupowanie,
    fallback HEVC/H.264, strumieniowe dekodowanie, retry na zerwane
    połączenie) żyje w jednym miejscu, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo."""
    sorted_items = sorted(items, key=lambda it: it[1])
    begin_dt = datetime.datetime.strptime(segment["BeginTime"], DATE_FMT)
    offsets = [(it, (it[1] - begin_dt).total_seconds()) for it in sorted_items]
    max_offset = max(off for _, off in offsets)

    done = 0
    failed = 0
    last_err: Exception | None = None
    t0 = time.time()
    # Do `retries` prób — długie ciągłe sesje na tym sprzęcie bywają
    # niestabilne (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo), więc zerwane połączenie przy pierwszej
    # próbie nie powinno od razu skreślać całej grupy celów (wzorzec retry
    # jak w `query_range_files`, tylko tu od nowa od BeginTime segmentu, bo
    # wznowienie w środku pliku nie działa niezawodnie).
    for attempt in range(retries):
        try:
            raw_data, fps = grab_segment_frames(
                host, port, user, password, channel,
                segment["FileName"], segment["BeginTime"], segment["EndTime"],
                max_offset, timeout,
            )
            video_payloads, _ = extract_video_frames(raw_data)
            if not video_payloads:
                raise ValueError("brak kompletnych ramek wideo w odebranych danych")
            elementary = b"".join(video_payloads)
            # Kodek archiwum NIE jest jednoznacznie przewidywalny z samego
            # live RTSP/nazwy pliku (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo — na Rejestratorze #1
            # archiwum bywało HEVC mimo że nazwa pliku sugerowała h264) —
            # spróbuj HEVC, a jeśli się nie da zdekodować, H.264 (urządzenia
            # analogowe/AHD, np. Rejestrator #2/#3, nagrywają w H.264).
            # WAŻNE — realny bug znaleziony przy testach: `av.open(...,
            # format="hevc")` na PRAWDZIWYCH danych H.264 NIE rzuca wyjątku
            # przy samym otwarciu (surowy strumień Annex-B nie jest ściśle
            # walidowany na tym etapie) — dopiero PRÓBA odebrania klatki z
            # dekodera cicho zwraca zero wyników. Poprawka: w bloku `try`
            # wymuś odebranie PIERWSZEJ klatki (`next(decoder)`) — dopiero to
            # naprawdę weryfikuje, że wybrany kodek pasuje.
            decoder = None
            for fmt in ("hevc", "h264"):
                try:
                    container = av.open(io.BytesIO(elementary), format=fmt)
                    candidate = container.decode(video=0)
                    first_frame = next(candidate)  # wymusza realny dekoding, nie tylko open()
                    decoder = itertools.chain([first_frame], candidate)
                    break
                except Exception:
                    continue
            if decoder is None:
                raise ValueError("PyAV nie potrafił otworzyć strumienia (ani hevc, ani h264)")

            # WAŻNE: `list(decoder)` materializowałby WSZYSTKIE zdekodowane
            # klatki naraz w RAM — dla długiego segmentu (tysiące klatek
            # 1080p+) to potrafi wymagać dziesiątek GB i kończyć się cichym
            # brakiem wyniku (empirycznie znaleziony bug: 900s segmentu na
            # tym sprzęcie dawało 0 klatek przy `list(...)`, mimo że dane
            # wejściowe były poprawne — patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo). Zamiast tego
            # iterujemy PO KOLEI, zapisujemy tylko klatki faktycznie
            # potrzebne dla celów w tej grupie i od razu zwalniamy resztę.
            target_queue = list(offsets)  # [(item, offset), ...], już posortowane po offset
            next_ptr = 0
            last_frame = None
            last_idx = -1
            decoded_count = 0
            for idx, frame in enumerate(decoder):
                decoded_count += 1
                last_frame, last_idx = frame, idx
                while next_ptr < len(target_queue) and int(round(target_queue[next_ptr][1] * fps)) <= idx:
                    (label, target_dt, out_path), offset = target_queue[next_ptr]
                    frame.to_image().save(out_path, quality=90)
                    done += 1
                    print(f"  [{label}] OK (klatka {idx}, ~t={idx/fps:.1f}s od początku "
                          f"segmentu, {frame.width}x{frame.height})")
                    next_ptr += 1
                if next_ptr >= len(target_queue):
                    break  # wszystkie cele tej grupy obsłużone — nie dekoduj dalej bez potrzeby
            if decoded_count == 0:
                raise ValueError("PyAV nie zdekodował żadnej klatki")

            # Cele, dla których zabrakło klatek (połączenie urwało się przed
            # dotarciem do ich przesunięcia) — użyj ostatniej dostępnej klatki
            # zamiast całkowitej porażki dla tej grupy.
            while next_ptr < len(target_queue):
                (label, target_dt, out_path), offset = target_queue[next_ptr]
                if last_frame is not None:
                    last_frame.to_image().save(out_path, quality=90)
                    done += 1
                    print(f"  [{label}] OK, ALE ograniczone (chciano klatkę "
                          f"~{int(round(offset*fps))}, dostępne tylko do {last_idx} — "
                          f"transfer urwał się wcześniej, użyto ostatniej dostępnej "
                          f"klatki zamiast właściwej)")
                else:
                    failed += 1
                    print(f"  [{label}] BŁĄD (brak jakiejkolwiek klatki)")
                next_ptr += 1

            elapsed = time.time() - t0
            print(f"Segment {segment['FileName']}: pobrano {len(raw_data)}B, "
                  f"zdekodowano {decoded_count} klatek @ {fps}fps w {elapsed:.1f}s.")
            return done, failed
        except Exception as e:
            last_err = e
            if attempt < retries - 1:
                print(f"Segment {segment['FileName']}: próba {attempt+1} nieudana ({e}), "
                      f"ponawiam od nowa...")
    print(f"Segment {segment['FileName']} ({len(items)} celów): "
          f"BŁĄD po {retries} próbach ({time.time()-t0:.1f}s): {last_err}")
    return 0, len(items)


def main():
    ap = argparse.ArgumentParser(
        description="Klatka co zadany krok czasowy z nagrań XMEYE dla wskazanego dnia/okna"
    )
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, required=True, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--date", required=True, help="YYYY-MM-DD")
    ap.add_argument("--out-dir", required=True, help="folder wyjściowy")
    ap.add_argument("--step", default="1min", choices=STEP_CHOICES,
                     help=f"krok między klatkami — jedna z: {', '.join(STEP_CHOICES)} "
                          f"(domyślnie 1min)")
    ap.add_argument("--start", default="00:00", help="HH:MM, opcjonalnie — domyślnie 00:00 (początek dnia)")
    ap.add_argument("--end", default="23:59", help="HH:MM, opcjonalnie — domyślnie 23:59 (koniec dnia)")
    ap.add_argument("--timeout", type=float, default=180.0,
                     help="budżet cierpliwości per klatka (s) — patrz ostrzeżenie w docstringu")
    args = ap.parse_args()

    try:
        step = parse_step(args.step)
    except argparse.ArgumentTypeError as e:
        ap.error(str(e))

    os.makedirs(args.out_dir, exist_ok=True)

    start_dt = datetime.datetime.strptime(f"{args.date} {args.start}", "%Y-%m-%d %H:%M")
    end_dt = datetime.datetime.strptime(f"{args.date} {args.end}", "%Y-%m-%d %H:%M")

    # Szukaj tylko w faktycznie potrzebnym oknie (+/- 1 min na granice segmentów),
    # nie zawsze całego dnia — szybsze i mniej podatne na niestabilność sprzętu
    # przy testach na krótkim wycinku.
    query_start = (start_dt - datetime.timedelta(minutes=1)).strftime(DATE_FMT)
    query_end = (end_dt + datetime.timedelta(minutes=1)).strftime(DATE_FMT)

    print(f"Krok: {args.step} ({step.total_seconds():.0f}s)")
    print(f"Szukam nagrań: kanał {args.channel}, {query_start} .. {query_end}...")
    files = query_range_files(args.host, args.port, args.user, args.password,
                               args.channel, query_start, query_end)
    print(f"Znaleziono {len(files)} segmentów nagrań w tym oknie.\n")

    targets = []
    cur = start_dt
    while cur <= end_dt:
        targets.append(cur)
        cur += step

    print(f"Cel: {len(targets)} klatek ({args.start} - {args.end}, co {args.step}), "
          f"zapis do {args.out_dir}\n")

    done = 0
    skipped_existing = 0
    skipped_no_segment = 0
    failed = 0
    t_run_start = time.time()

    # Grupuj cele po segmencie nagrania, do którego trafiają — segmenty ciągłe
    # ("[R]") potrafią trwać kilkanaście minut/godzin, więc wiele kolejnych
    # docelowych momentów (np. co 1min) często trafia w TEN SAM segment.
    # WAŻNE: to NIE znaczy, że dostają tę samą klatkę — każdy dostaje klatkę z
    # WŁAŚCIWEGO przesunięcia czasowego w segmencie (patrz `grab_segment_frames`
    # niżej). Wcześniejsza wersja tego skryptu myliła "ten sam segment" z "ta
    # sama klatka" i kopiowała identyczne zdjęcie do wszystkich celów w
    # segmencie — realny bug, znaleziony przy teście na Rejestratorze #2.
    groups: dict[str, dict] = {}  # FileName -> {"segment":..., "items":[(label, target_dt, out_path)]}
    for i, target_dt in enumerate(targets):
        hhmmss = target_dt.strftime("%H:%M:%S")
        out_path = os.path.join(args.out_dir, f"{args.channel}_{args.date}_{hhmmss}.jpg")
        if os.path.exists(out_path):
            skipped_existing += 1
            continue
        segment = find_segment(files, target_dt)
        if segment is None:
            print(f"{hhmmss}: brak nagrania w tym momencie, pomijam")
            skipped_no_segment += 1
            continue
        group = groups.setdefault(segment["FileName"], {"segment": segment, "items": []})
        group["items"].append((f"{i+1}/{len(targets)} {hhmmss}", target_dt, out_path))

    print(f"{len(groups)} unikalnych segmentów obejmuje cele do pobrania "
          f"({sum(len(g['items']) for g in groups.values())} klatek).\n")

    for group in groups.values():
        seg_done, seg_failed = fetch_segment_targets(
            args.host, args.port, args.user, args.password, args.channel,
            group["segment"], group["items"], args.timeout,
        )
        done += seg_done
        failed += seg_failed

    total_time = time.time() - t_run_start
    print(f"\n=== KONIEC ===")
    print(f"Pobrane: {done}, pominięte (już istniały): {skipped_existing}, "
          f"pominięte (brak nagrania): {skipped_no_segment}, błędy: {failed}")
    print(f"Czas: {total_time/60:.1f} min")


if __name__ == "__main__":
    main()
