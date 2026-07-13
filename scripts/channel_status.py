#!/usr/bin/env python3
"""
channel_status.py — status połączenia kamer na kanałach rejestratora XMEYE (DVRIP).

Faza 0 z PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, sekcja "Do zrobienia": na Rejestratorze #1 kanały 4 i 5 mają
fizycznie podpięte kamery, kanały 1-3 są CELOWO bez kamery (test obsługi błędów).
Ten skrypt pobiera "NetWork.ChnStatus" i "ChannelTitle" (nazwy configów community,
python-dvr/OpenIPC — msg_id 1042 i 1048) i pokazuje surową odpowiedź per kanał,
żeby ustalić jak rejestrator sygnalizuje offline/błąd połączenia w tym firmware.

UWAGA: nazwa configu "NetWork.ChnStatus" jest wiedzą community, nie potwierdzoną
jeszcze na tym konkretnym firmware — jeśli parsowanie się nie uda, skrypt i tak
wypisze surowe bajty odpowiedzi do porównania ze zrzutem Wireshark (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo,
"Ścieżka rozpoznania bez appki").

Użycie:
    python3 channel_status.py --host 192.168.1.100 --user tester --password 'HASLO!'
"""

import argparse
import json
import socket
import sys

from identify_nvr import DVRIPClient

# Oczekiwany stan fizyczny na Rejestratorze #1 (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo) — do porównania
# z tym, co realnie zwróci rejestrator.
EXPECTED_CONNECTED_CHANNELS = {4, 5}
EXPECTED_DISCONNECTED_CHANNELS = {1, 2, 3}


def main():
    ap = argparse.ArgumentParser(description="Status kanałów kamer rejestratora XMEYE")
    ap.add_argument("--host", required=True, help="IP rejestratora")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--dvrip-port", type=int, default=34567)
    args = ap.parse_args()

    client = DVRIPClient(args.host, args.dvrip_port)
    try:
        client.connect()
    except OSError as e:
        print(f"Błąd połączenia z {args.host}:{args.dvrip_port}: {e}")
        sys.exit(1)

    try:
        _, login_parsed, _, _ = client.login(args.user, args.password)
        if not login_parsed:
            print("Logowanie: brak/nieparsowalna odpowiedź.")
            sys.exit(1)
        if login_parsed.get("Ret") not in (100, "100"):
            print(f"Logowanie nieudane (Ret={login_parsed.get('Ret')}).")
            sys.exit(1)
        print(f"Zalogowano, SessionID=0x{client.session_id:08X}\n")

        print("--- ChannelTitle (nazwy kanałów) ---")
        _, titles, header_raw, payload_raw = client.get_channel_titles()
        if titles is not None:
            print(json.dumps(titles, indent=2, ensure_ascii=False))
        else:
            print("Nie udało się sparsować — surowe bajty:")
            print(f"  header: {header_raw!r}")
            print(f"  payload: {payload_raw!r}")

        print("\n--- NetWork.ChnStatus (status połączenia per kanał) ---")
        _, status, header_raw, payload_raw = client.get_channel_status()
        if status is not None:
            print(json.dumps(status, indent=2, ensure_ascii=False))
            print("\n--- Porównanie z oczekiwanym stanem fizycznym ---")
            print(f"Oczekiwane podłączone: kanały {sorted(EXPECTED_CONNECTED_CHANNELS)}")
            print(f"Oczekiwane odłączone (test błędów): kanały {sorted(EXPECTED_DISCONNECTED_CHANNELS)}")
            print("Zweryfikuj ręcznie powyższy JSON względem tego — dopiero na tej")
            print("podstawie da się ustalić, które pole/wartość oznacza 'brak sygnału'.")
        else:
            print("Nie udało się sparsować — surowe bajty:")
            print(f"  header: {header_raw!r}")
            print(f"  payload: {payload_raw!r}")
            print("\nMożliwe, że nazwa configu 'NetWork.ChnStatus' nie pasuje do tego")
            print("firmware. Kolejny krok: przechwycić ruch panelu web (DevTools + tcpdump)")
            print("podczas przeglądania statusu kanałów w GUI i porównać nazwę configu")
            print("— patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, sekcja 'Ścieżka rozpoznania bez appki'.")

    except socket.timeout:
        print("Timeout — brak odpowiedzi od rejestratora.")
    except Exception as e:
        print(f"Nieoczekiwany błąd: {e}")
    finally:
        client.close()


if __name__ == "__main__":
    main()
