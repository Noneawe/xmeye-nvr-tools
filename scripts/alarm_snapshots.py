#!/usr/bin/env python3
"""
alarm_snapshots.py — znajdź alarmy (nagrania [M], czyli wyzwolone ruchem/
zdarzeniem, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo "Nagranie z konkretnego alarmu") dla danego
kanału i dnia, i dla KAŻDEGO z nich pobierz serię zdjęć zaczynającą się od
momentu ustąpienia alarmu (EndTime segmentu [M]), w regularnych odstępach
(--step), przez zadany czas po alarmie (--after-duration).

Nie duplikuje logiki pobierania/dekodowania — importuje ją bezpośrednio z
`periodic_snapshots.py` (OPFileQuery, grupowanie po segmencie, fallback
HEVC→H.264, strumieniowe dekodowanie, retry na zerwane połączenie — patrz
PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, sekcja o trzech bugach znalezionych w tamtym skrypcie). Ten skrypt
dogrywa TYLKO wyszukiwanie alarmów i budowę listy docelowych momentów
(EndTime, EndTime+step, EndTime+2*step, ...) — resztę robi ten sam,
sprawdzony `fetch_segment_targets()`.

WAŻNE — dlaczego to NIE jest proste wywołanie periodic_snapshots.py jako
podprocesu: `--start`/`--end` tamtego skryptu mają precyzję MINUTOWĄ (sekundy
są obcinane), a moment ustąpienia alarmu ma dowolne sekundy i krok bywa
5-15s — różnica rzędu prawie minuty byłaby nie do zaakceptowania przy takiej
precyzji. Dlatego docelowe momenty są budowane tutaj bezpośrednio z
EndTime segmentu [M] (pełna precyzja sekundowa), a nie przez CLI tamtego
skryptu.

Struktura wyjścia — jeden podfolder per znaleziony alarm (żeby nie było
niejasne, do którego alarmu należy które zdjęcie):
    <out-dir>/alarm_01_07-15-32/+000s.jpg
    <out-dir>/alarm_01_07-15-32/+005s.jpg
    <out-dir>/alarm_01_07-15-32/+010s.jpg
    ...
    <out-dir>/alarm_02_08-02-11/+000s.jpg
    ...
(nazwa folderu = numer alarmu tego dnia + HH-MM-SS momentu ustąpienia)

Użycie:
    python3 alarm_snapshots.py --host 192.168.1.100 --user admin \
        --password 'YOUR_PASSWORD' --channel 0 --date 2026-07-10 \
        --step 5sec --after-duration 30sec --out-dir /sciezka/do/folderu
    (channel liczone OD 0, jak w periodic_snapshots.py — kanał fizyczny 1 = 0)

    Tylko alarmy z okna 06:00-10:00, zdjęcia co 10s przez minutę po każdym:
    python3 alarm_snapshots.py ... --window-start 06:00 --window-end 10:00 \
        --step 10sec --after-duration 1min

Zależności: takie same jak periodic_snapshots.py (`pip install av pillow`),
ten skrypt musi leżeć w tym samym katalogu (import).
"""

import argparse
import datetime
import os
import sys
import time

try:
    import periodic_snapshots as ps
except ImportError:
    print("Nie znaleziono periodic_snapshots.py — musi być w tym samym "
          "katalogu co alarm_snapshots.py (ten skrypt importuje jego logikę "
          "pobierania/dekodowania zamiast duplikować ją).")
    sys.exit(1)

# Czas trwania "po alarmie" to wartość CIĄGŁA (nie zamknięty zestaw jak
# --step) — reużywamy tego samego parsera co periodic_snapshots.py
# (STEP_RE/parse_step obsługuje dowolne "<liczba><min|sec>"), tylko bez
# ograniczenia do STEP_CHOICES.
parse_duration = ps.parse_step


def find_alarm_segments(files: list[dict]) -> list[dict]:
    """Segmenty `[M]` (wyzwolone ruchem/zdarzeniem, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo) —
    każdy traktowany jako jeden "alarm": BeginTime = start alarmu,
    EndTime = moment ustąpienia (koniec nagrywania zdarzenia)."""
    alarms = [f for f in files if "[M]" in f.get("FileName", "")]
    alarms.sort(key=lambda f: f["BeginTime"])
    return alarms


def main():
    ap = argparse.ArgumentParser(
        description="Zdjęcia z okresu PO każdym alarmie (nagraniu [M]) danego dnia/kanału"
    )
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, required=True, help="0-based (kanał fizyczny 4 = 3)")
    ap.add_argument("--date", required=True, help="YYYY-MM-DD — dzień, w którym szukać alarmów")
    ap.add_argument("--out-dir", required=True, help="folder wyjściowy (jeden podfolder per alarm)")
    ap.add_argument("--step", default="5sec", choices=ps.STEP_CHOICES,
                     help=f"odstęp między zdjęciami PO alarmie — jedna z: "
                          f"{', '.join(ps.STEP_CHOICES)} (domyślnie 5sec)")
    ap.add_argument("--after-duration", default="30sec",
                     help="jak długo po ustąpieniu alarmu robić zdjęcia, np. '30sec', "
                          "'1min', '2min' (domyślnie 30sec)")
    ap.add_argument("--window-start", default="00:00",
                     help="HH:MM, opcjonalnie — szukaj alarmów tylko od tej godziny (domyślnie 00:00)")
    ap.add_argument("--window-end", default="23:59",
                     help="HH:MM, opcjonalnie — szukaj alarmów tylko do tej godziny (domyślnie 23:59)")
    ap.add_argument("--timeout", type=float, default=180.0,
                     help="budżet cierpliwości per segment (s) — patrz periodic_snapshots.py")
    args = ap.parse_args()

    try:
        step = parse_duration(args.step)
    except argparse.ArgumentTypeError as e:
        ap.error(str(e))
    try:
        after_duration = parse_duration(args.after_duration)
    except argparse.ArgumentTypeError as e:
        ap.error(f"--after-duration: {e}")

    os.makedirs(args.out_dir, exist_ok=True)

    window_start_dt = datetime.datetime.strptime(f"{args.date} {args.window_start}", "%Y-%m-%d %H:%M")
    window_end_dt = datetime.datetime.strptime(f"{args.date} {args.window_end}", "%Y-%m-%d %H:%M")
    # Szukaj trochę szerzej niż samo okno alarmów, żeby złapać też segmenty
    # PO ostatnim alarmie (do których wpadną docelowe momenty po ustąpieniu,
    # patrz --after-duration) — margines = after_duration + 1 minuta zapasu.
    query_start = (window_start_dt - datetime.timedelta(minutes=1)).strftime(ps.DATE_FMT)
    query_end = (window_end_dt + after_duration + datetime.timedelta(minutes=1)).strftime(ps.DATE_FMT)

    print(f"Szukam nagrań: kanał {args.channel}, {query_start} .. {query_end}...")
    files = ps.query_range_files(args.host, args.port, args.user, args.password,
                                  args.channel, query_start, query_end)
    print(f"Znaleziono {len(files)} segmentów nagrań w tym oknie.")

    alarms = find_alarm_segments(files)
    alarms = [a for a in alarms
              if window_start_dt <= datetime.datetime.strptime(a["BeginTime"], ps.DATE_FMT) <= window_end_dt]
    print(f"Znaleziono {len(alarms)} alarmów ({args.window_start}-{args.window_end}).\n")

    if not alarms:
        print("Brak alarmów w tym oknie — nic do zrobienia.")
        return

    total_done = 0
    total_failed = 0
    total_skipped_no_segment = 0
    t_run_start = time.time()

    for n, alarm in enumerate(alarms, start=1):
        alarm_begin = datetime.datetime.strptime(alarm["BeginTime"], ps.DATE_FMT)
        alarm_end = datetime.datetime.strptime(alarm["EndTime"], ps.DATE_FMT)
        print(f"=== Alarm {n}/{len(alarms)}: {alarm_begin:%H:%M:%S} -> "
              f"{alarm_end:%H:%M:%S} (ustąpił o {alarm_end:%H:%M:%S}) ===")

        alarm_dir = os.path.join(
            args.out_dir, f"alarm_{n:02d}_{alarm_end:%H-%M-%S}"
        )
        os.makedirs(alarm_dir, exist_ok=True)

        # Docelowe momenty: EndTime, EndTime+step, EndTime+2*step, ... aż do
        # EndTime+after_duration — PEŁNA precyzja sekundowa (nie HH:MM).
        targets = []
        cur = alarm_end
        limit = alarm_end + after_duration
        while cur <= limit:
            targets.append(cur)
            cur += step

        # Grupuj po segmencie, do którego trafia każdy moment — po alarmie
        # nagrywanie zwykle kontynuuje się w NASTĘPNYM (często [R], ciągłym)
        # segmencie, nie w tym samym [M], który już się skończył dokładnie
        # w alarm_end — patrz `fetch_segment_targets` w periodic_snapshots.py.
        groups: dict[str, dict] = {}
        for target_dt in targets:
            offset_s = (target_dt - alarm_end).total_seconds()
            out_path = os.path.join(alarm_dir, f"+{int(round(offset_s)):03d}s.jpg")
            if os.path.exists(out_path):
                continue
            segment = ps.find_segment(files, target_dt)
            if segment is None:
                print(f"  +{offset_s:.0f}s ({target_dt:%H:%M:%S}): brak nagrania w tym "
                      f"momencie, pomijam")
                total_skipped_no_segment += 1
                continue
            group = groups.setdefault(segment["FileName"], {"segment": segment, "items": []})
            group["items"].append((f"alarm{n} +{offset_s:.0f}s", target_dt, out_path))

        for group in groups.values():
            done, failed = ps.fetch_segment_targets(
                args.host, args.port, args.user, args.password, args.channel,
                group["segment"], group["items"], args.timeout,
            )
            total_done += done
            total_failed += failed
        print()

    total_time = time.time() - t_run_start
    print("=== KONIEC ===")
    print(f"Alarmów: {len(alarms)}, zdjęć zapisanych: {total_done}, "
          f"błędów: {total_failed}, pominiętych (brak nagrania): {total_skipped_no_segment}")
    print(f"Czas: {total_time/60:.1f} min")


if __name__ == "__main__":
    main()
