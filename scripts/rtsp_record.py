#!/usr/bin/env python3
"""
rtsp_record.py — nagraj N sekund z GŁÓWNEGO strumienia RTSP (stream=0, "Main")
dla wskazanego kanału, bez rekodowania (czysty remux przez PyAV/FFmpeg), i wypisz
jakie strumienie (wideo/audio, kodeki) faktycznie są w źródle.

Kontekst: oficjalna appka XMEye Pro nie łączy się z głównym strumieniem tego
rejestratora — ten skrypt sprawdza, czy RTSP (potwierdzony działający w Fazie 1,
patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo) daje sobie z tym radę niezależnie od appki.

Format URL RTSP potwierdzony wcześniej: rtsp://<ip>:554/user=..&password=..&channel=<N>&stream=0.sdp
(N liczone OD 1, jak reszta RTSP w tym projekcie — inaczej niż OPMonitor/AlarmInfo).

Zależności: `pip install av` (ten sam venv co snapshot_from_opmonitor.py itd.)

Użycie:
    python3 rtsp_record.py --host 192.168.1.100 --user tester --password 'HASLO!' \
        --channel 4 --duration 15 --out kanal4_main.mkv
"""

import argparse
import sys
import time
from urllib.parse import quote

try:
    import av
except ImportError:
    print("Brakuje pakietu 'av' (PyAV). Zainstaluj: pip install av")
    sys.exit(1)


def record(url: str, out_path: str, duration: float, connect_timeout: float, read_timeout: float) -> None:
    print(f"Łączę: {url}")
    input_container = av.open(
        url,
        options={"rtsp_transport": "tcp"},
        # (timeout_otwarcia, timeout_odczytu) - ten sprzęt bywa niestabilny w
        # trakcie transferu (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo), read_timeout musi mieć duży zapas.
        timeout=(connect_timeout, read_timeout),
    )

    print("\n--- Strumienie w źródle ---")
    for s in input_container.streams:
        codec_name = s.codec_context.name if s.codec_context else "?"
        print(f"  [{s.index}] typ={s.type} kodek={codec_name} time_base={s.time_base}")
    n_video = len(input_container.streams.video)
    n_audio = len(input_container.streams.audio)
    print(f"\nWideo: {n_video} strumień/strumienie, Audio: {n_audio} strumień/strumienie")
    if n_audio == 0:
        print("BRAK ŚCIEŻKI AUDIO w tym strumieniu.")
    else:
        for a in input_container.streams.audio:
            print(f"  Audio: kodek={a.codec_context.name}, sample_rate={a.codec_context.sample_rate}, "
                  f"channels={a.codec_context.channels}")

    output_container = av.open(out_path, mode="w")
    stream_map = {}
    for s in input_container.streams:
        try:
            out_s = output_container.add_stream_from_template(s)
            stream_map[s.index] = out_s
        except ValueError as exc:
            # Kontener wyjściowy nie obsługuje tego kodeka (np. AVI + HEVC).
            # Strumień i tak już zaraportowany wyżej (obecność/kodek) - pomijamy
            # tylko sam zapis do pliku dla tego strumienia.
            print(f"  UWAGA: strumień [{s.index}] ({s.type}, {s.codec_context.name}) "
                  f"pominięty w pliku wyjściowym: {exc}")

    print(f"\n--- Nagrywam {duration:.0f}s do {out_path} ---")
    t_start = time.monotonic()
    t_first_packet: float | None = None
    n_packets = 0
    n_video_packets = 0
    n_audio_packets = 0
    error: Exception | None = None
    try:
        for packet in input_container.demux():
            now = time.monotonic()
            if packet.dts is None and packet.pts is None:
                continue  # tylko puste pakiety "flush", nie prawdziwe dane bez dts
            if t_first_packet is None:
                t_first_packet = now
                print(f"  (pierwszy pakiet po {now - t_start:.1f}s od połączenia)")
            print(f"    pakiet: typ={packet.stream.type} rozmiar={packet.size}B "
                  f"pts={packet.pts} t={now - t_start:.1f}s", flush=True)
            # Licz czas nagrania OD pierwszego realnego pakietu, nie od otwarcia
            # połączenia — kanały 4K/HEVC potrafią buforować kilkanaście sekund,
            # zanim cokolwiek popłynie; liczenie od connect ucinało nagranie do zera.
            if now - t_first_packet > duration:
                break
            out_s = stream_map.get(packet.stream.index)
            if out_s is None:
                continue
            if packet.dts is None:
                packet.dts = packet.pts
            packet.stream = out_s
            output_container.mux(packet)
            n_packets += 1
            if packet.stream.type == "video":
                n_video_packets += 1
            elif packet.stream.type == "audio":
                n_audio_packets += 1
    except Exception as exc:  # noqa: BLE001 - chcemy zaraportować i tak zamknąć plik
        error = exc
    finally:
        output_container.close()
        input_container.close()

    elapsed = time.monotonic() - t_start
    if error is not None:
        print(f"\n=== PRZERWANE po {elapsed:.1f}s: {type(error).__name__}: {error} ===")
    else:
        print(f"\n=== Zakończono po {elapsed:.1f}s ===")
    print(f"Zmuxowane pakiety: {n_packets} (wideo={n_video_packets}, audio={n_audio_packets})")
    if error is not None:
        raise error


def main() -> None:
    ap = argparse.ArgumentParser(description="Nagraj N sekund z głównego strumienia RTSP")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=554)
    ap.add_argument("--channel", type=int, required=True, help="1-based (konwencja RTSP)")
    ap.add_argument("--stream", type=int, default=0, choices=[0, 1], help="0=Main, 1=Extra1")
    ap.add_argument("--duration", type=float, default=15.0)
    ap.add_argument("--connect-timeout", type=float, default=15.0)
    ap.add_argument("--read-timeout", type=float, default=60.0,
                     help="budżet na pojedynczy odczyt w trakcie nagrywania (sprzęt bywa niestabilny)")
    ap.add_argument("--out", required=True,
                     help="np. kanal4.avi (h264+alaw) albo kanal5.mkv (hevc; alaw audio "
                          "zostanie pominięty w pliku, MKV go nie obsługuje)")
    args = ap.parse_args()

    user = quote(args.user, safe="")
    password = quote(args.password, safe="")
    # Urządzenie wymaga danych logowania OSADZONYCH w ścieżce (jego własna
    # konwencja, patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo/rtsp_probe.py) — ALE serwer i tak odpowiada
    # standardowym wyzwaniem RTSP Digest (401), które FFmpeg/PyAV obsłuży
    # automatycznie TYLKO jeśli dane logowania są też w standardowym miejscu
    # URI (user:pass@host). Stąd oba naraz.
    url = (f"rtsp://{user}:{password}@{args.host}:{args.port}/"
           f"user={user}&password={password}&channel={args.channel}&stream={args.stream}.sdp")

    record(url, args.out, args.duration, args.connect_timeout, args.read_timeout)


if __name__ == "__main__":
    main()
