#!/usr/bin/env python3
"""
concurrent_sessions_test.py — test wielu jednoczesnych sesji DVRIP per rejestrator
(Faza 3, PROTOCOL_NOTES.md in the ha-xmeye-nvr repo: "Obsługa wielu jednoczesnych sesji (podgląd + alarmy równolegle)
per rejestrator"). Uruchamia RÓWNOLEGLE, przez dłuższy czas:

  1. Wątek "coordinator" — polling NetWork.ChnStatus + SystemInfo co UPDATE_INTERVAL
     (jak prawdziwy coordinator.py), własne połączenie DVRIP.
  2. Wątek "alarm listener" — push AlarmInfo (jak alarm_listener.py), osobne
     połączenie DVRIP.
  3. Wątek "RTSP prober" — okresowe DESCRIBE na strumieniu kamery (jak camera.py by
     robił przez stream platform), osobne połączenie na porcie 554 (nie liczy się
     do limitu TCPMaxConn=10 na porcie 34567).

Cel: potwierdzić, że te trzy niezależne sesje nie blokują się nawzajem i wszystkie
trzy kończą się sukcesem przez cały czas trwania testu.

Użycie:
    python3 concurrent_sessions_test.py --host 192.168.1.100 --user tester \
        --password 'HASLO!' --channel 3 --duration 120
"""

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import threading
import time
from urllib.parse import quote

HEADER_FMT = "<BB2xII2xHI"
HEADER_LEN = struct.calcsize(HEADER_FMT)

MSG_LOGIN_REQ = 1000
MSG_KEEPALIVE_REQ = 1006
MSG_ALARM_SET_REQ = 1500
MSG_ALARM_INFO = 1504
MSG_CONFIG_GET = 1042


def sofia_hash(password: str) -> str:
    md5_digest = hashlib.md5(password.encode("utf-8")).digest()
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    return "".join(chars[(a + b) % 62] for a, b in zip(md5_digest[::2], md5_digest[1::2]))


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.counts = {}
        self.errors = {}

    def ok(self, label):
        with self.lock:
            self.counts[label] = self.counts.get(label, 0) + 1

    def fail(self, label, err):
        with self.lock:
            self.errors.setdefault(label, []).append(str(err))

    def report(self):
        print("\n=== WYNIKI ===")
        for label in sorted(set(self.counts) | set(self.errors)):
            ok = self.counts.get(label, 0)
            errs = self.errors.get(label, [])
            print(f"{label}: {ok} sukcesów, {len(errs)} błędów")
            for e in errs[:5]:
                print(f"    {e}")


def read_exact(sock, n, timeout=10.0):
    data = b""
    sock.settimeout(timeout)
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("połączenie zamknięte")
        data += chunk
    return data


# --- Wątek 1: coordinator-style polling ---

def coordinator_thread(host, port, user, password, channel_num, interval, stop_event, stats):
    sock = None
    session_id = 0
    seq = 0

    def send(msg_id, payload):
        nonlocal seq
        body = json.dumps(payload).encode() + b"\x0a\x00"
        header = struct.pack(HEADER_FMT, 0xFF, 0, session_id, seq, msg_id, len(body))
        sock.sendall(header + body)
        seq += 1

    def recv_json():
        h = read_exact(sock, HEADER_LEN)
        _, _, _, _, _, plen = struct.unpack(HEADER_FMT, h)
        p = read_exact(sock, plen) if plen else b""
        return json.loads(p.rstrip(b"\x00\x0a").decode())

    while not stop_event.is_set():
        try:
            if sock is None:
                sock = socket.create_connection((host, port), timeout=10)
                session_id = 0
                seq = 0
                send(MSG_LOGIN_REQ, {"EncryptType": "MD5", "LoginType": "DVRIP-Web",
                                      "PassWord": sofia_hash(password), "UserName": user})
                d = recv_json()
                if d.get("Ret") not in (100, "100"):
                    raise RuntimeError(f"login odrzucony: {d}")
                session_id = int(d["SessionID"], 16)

            send(MSG_CONFIG_GET, {"Name": "NetWork.ChnStatus", "SessionID": f"0x{session_id:08X}"})
            resp = recv_json()
            n_connected = sum(1 for s in resp.get("NetWork.ChnStatus", [])[:channel_num]
                               if s.get("Status") == "Connected")
            stats.ok("coordinator")
            print(f"  [coordinator] poll OK, {n_connected} kanałów Connected", flush=True)
        except Exception as e:
            stats.fail("coordinator", e)
            print(f"  [coordinator] BŁĄD: {e}", flush=True)
            if sock:
                sock.close()
            sock = None
        stop_event.wait(interval)

    if sock:
        sock.close()


# --- Wątek 2: alarm listener ---

def alarm_thread(host, port, user, password, stop_event, stats):
    while not stop_event.is_set():
        sock = None
        try:
            sock = socket.create_connection((host, port), timeout=10)
            seq = 0

            def send(msg_id, payload):
                nonlocal seq
                body = json.dumps(payload).encode() + b"\x0a\x00"
                header = struct.pack(HEADER_FMT, 0xFF, 0, session_id, seq, msg_id, len(body))
                sock.sendall(header + body)
                seq += 1

            def recv_json():
                h = read_exact(sock, HEADER_LEN)
                _, _, _, _, _, plen = struct.unpack(HEADER_FMT, h)
                p = read_exact(sock, plen) if plen else b""
                return json.loads(p.rstrip(b"\x00\x0a").decode())

            send_login = json.dumps({"EncryptType": "MD5", "LoginType": "DVRIP-Web",
                                      "PassWord": sofia_hash(password), "UserName": user}).encode() + b"\x0a\x00"
            header = struct.pack(HEADER_FMT, 0xFF, 0, 0, 0, MSG_LOGIN_REQ, len(send_login))
            sock.sendall(header + send_login)
            h = read_exact(sock, HEADER_LEN)
            _, _, _, _, _, plen = struct.unpack(HEADER_FMT, h)
            p = read_exact(sock, plen)
            d = json.loads(p.rstrip(b"\x00\x0a").decode())
            if d.get("Ret") not in (100, "100"):
                raise RuntimeError(f"login odrzucony: {d}")
            session_id = int(d["SessionID"], 16)
            seq = 1

            send(MSG_ALARM_SET_REQ, {"Name": "", "SessionID": f"0x{session_id:08X}"})
            recv_json()
            stats.ok("alarm_subscribe")
            print("  [alarm] subskrypcja OK, nasłuchuję...", flush=True)

            sock.settimeout(2.0)
            last_keepalive = time.monotonic()
            while not stop_event.is_set():
                if time.monotonic() - last_keepalive > 15:
                    send(MSG_KEEPALIVE_REQ, {"Name": "KeepAlive", "SessionID": f"0x{session_id:08X}"})
                    last_keepalive = time.monotonic()
                try:
                    h = read_exact(sock, HEADER_LEN, timeout=2.0)
                except socket.timeout:
                    continue
                _, _, _, _, msg_id, plen = struct.unpack(HEADER_FMT, h)
                payload = read_exact(sock, plen, timeout=5.0) if plen else b""
                if msg_id == MSG_ALARM_INFO:
                    stats.ok("alarm_event")
                    try:
                        info = json.loads(payload.rstrip(b"\x00\x0a").decode())["AlarmInfo"]
                        print(f"  [alarm] ZDARZENIE: kanał={info.get('Channel')} "
                              f"event={info.get('Event')} status={info.get('Status')}", flush=True)
                    except Exception:
                        print(f"  [alarm] ZDARZENIE (nieparsowalne)", flush=True)
        except Exception as e:
            stats.fail("alarm_listener", e)
            print(f"  [alarm] BŁĄD: {e}", flush=True)
        finally:
            if sock:
                sock.close()
        if not stop_event.is_set():
            stop_event.wait(5)


# --- Wątek 3: RTSP prober (osobny port, poza limitem TCPMaxConn) ---

def rtsp_thread(host, user, password, channel, interval, stop_event, stats):
    while not stop_event.is_set():
        try:
            sock = socket.create_connection((host, 554), timeout=10)
            url = f"rtsp://{host}:554/user={quote(user, safe='')}&password={quote(password, safe='')}&channel={channel}&stream=0.sdp"
            req = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 1\r\nAccept: application/sdp\r\n\r\n"
            sock.sendall(req.encode())
            sock.settimeout(10)
            data = sock.recv(4096).decode(errors="replace")
            if " 401 " in data.splitlines()[0]:
                import re
                m = re.search(r'WWW-Authenticate:\s*\S+\s+(.*)', data)
                params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
                ha1 = hashlib.md5(f"{user}:{params['realm']}:{password}".encode()).hexdigest()
                ha2 = hashlib.md5(f"DESCRIBE:{url}".encode()).hexdigest()
                digest = hashlib.md5(f"{ha1}:{params['nonce']}:{ha2}".encode()).hexdigest()
                auth = (f'Authorization: Digest username="{user}", realm="{params["realm"]}", '
                        f'nonce="{params["nonce"]}", uri="{url}", response="{digest}"')
                req2 = f"DESCRIBE {url} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n{auth}\r\n\r\n"
                sock.sendall(req2.encode())
                data = sock.recv(4096).decode(errors="replace")
            sock.close()
            if " 200 " in data.splitlines()[0]:
                stats.ok("rtsp")
                print("  [rtsp] DESCRIBE OK", flush=True)
            else:
                raise RuntimeError(f"nieoczekiwana odpowiedź: {data.splitlines()[0]}")
        except Exception as e:
            stats.fail("rtsp", e)
            print(f"  [rtsp] BŁĄD: {e}", flush=True)
        stop_event.wait(interval)


def main():
    ap = argparse.ArgumentParser(description="Test wielu jednoczesnych sesji DVRIP per rejestrator")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=34567)
    ap.add_argument("--channel", type=int, default=3, help="0-based dla coordinator, RTSP użyje +1")
    ap.add_argument("--channel-num", type=int, default=10)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--coordinator-interval", type=float, default=20.0)
    ap.add_argument("--rtsp-interval", type=float, default=25.0)
    args = ap.parse_args()

    stats = Stats()
    stop_event = threading.Event()

    threads = [
        threading.Thread(target=coordinator_thread, args=(
            args.host, args.port, args.user, args.password, args.channel_num,
            args.coordinator_interval, stop_event, stats), name="coordinator"),
        threading.Thread(target=alarm_thread, args=(
            args.host, args.port, args.user, args.password, stop_event, stats), name="alarm"),
        threading.Thread(target=rtsp_thread, args=(
            args.host, args.user, args.password, args.channel + 1,
            args.rtsp_interval, stop_event, stats), name="rtsp"),
    ]

    print(f"Startuję 3 równoległe sesje na {args.duration:.0f}s "
          f"(coordinator co {args.coordinator_interval:.0f}s, RTSP co {args.rtsp_interval:.0f}s, "
          f"alarm listener ciągle nasłuchuje)...\n")
    for t in threads:
        t.start()

    try:
        stop_event.wait(args.duration)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=15)

    stats.report()

    total_errors = sum(len(v) for v in stats.errors.values())
    if total_errors == 0:
        print("\nSUKCES: wszystkie trzy sesje działały równolegle bez błędów.")
    else:
        print(f"\nUWAGA: {total_errors} błędów w trakcie testu (patrz wyżej).")


if __name__ == "__main__":
    main()
