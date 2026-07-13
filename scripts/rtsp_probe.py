#!/usr/bin/env python3
"""
rtsp_probe.py — ustalenie działającego formatu RTSP URL na rejestratorze XMEYE.

Faza 1 z PROTOCOL_NOTES.md in the ha-xmeye-nvr repo: port 554 (RTSP) jest otwarty, ale format URL nieznany.
Zamiast zgadywać na oślep w kliencie wideo, ten skrypt wysyła surowe żądania
RTSP OPTIONS/DESCRIBE (tekstowy protokół, jak HTTP) do listy kandydackich
ścieżek i sprawdza kod odpowiedzi — 200 = trafiony format, 401 = wymaga innej
autoryzacji, 404 = zła ścieżka/kanał. To nie modyfikuje stanu rejestratora
(same żądania odczytu metadanych, bez odbierania strumienia wideo).

Testowane tylko na kanałach z realnie podpiętą kamerą (patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo —
Rejestrator #1: kanały 4 i 5), bo kanał bez kamery i tak nie zwróci sensownego
SDP nawet przy poprawnym formacie URL.

Użycie:
    python3 rtsp_probe.py --host 192.168.1.100 --user tester --password 'HASLO!' --channels 4,5
"""

import argparse
import base64
import hashlib
import re
import socket
import sys
from urllib.parse import quote

RTSP_PORT = 554
TIMEOUT = 4.0

# Kandydackie formaty ścieżek, znane z community dla rodziny Xiongmai/XMEYE/Sofia
# oraz kilku pokrewnych OEM-ów (Dahua-klony, generyczne NVR). {ch} = numer kanału
# liczony od 1, {ch0} = liczony od 0 (niektóre firmware indeksują od zera).
CANDIDATE_PATHS = [
    "/user={user}&password={password}&channel={ch}&stream=0.sdp",
    "/user={user}&password={password}&channel={ch}&stream=1.sdp",
    "/user={user}&password={password}&channel={ch0}&stream=0.sdp",
    "/cam/realmonitor?channel={ch}&subtype=0",
    "/cam/realmonitor?channel={ch}&subtype=1",
    "/live/ch{ch}",
    "/live/ch{ch0}",
    "/h264/ch{ch}/main/av_stream",
    "/onvif1",
    "/onvif{ch}",
    "/ch{ch0}0.264",
    "/ch{ch0}1.264",
    "/Streaming/Channels/{ch}01",
]


def build_paths(user: str, password: str, channels: list[int]):
    q_user = quote(user, safe="")
    q_pass = quote(password, safe="")
    paths = []
    for ch in channels:
        for tmpl in CANDIDATE_PATHS:
            path = tmpl.format(user=q_user, password=q_pass, ch=ch, ch0=ch - 1)
            paths.append((ch, path))
    return paths


def rtsp_request(sock: socket.socket, method: str, url: str, cseq: int, extra_headers=None):
    headers = [f"{method} {url} RTSP/1.0", f"CSeq: {cseq}", "User-Agent: rtsp_probe.py"]
    if extra_headers:
        headers.extend(extra_headers)
    req = "\r\n".join(headers) + "\r\n\r\n"
    sock.sendall(req.encode("utf-8"))
    return read_response(sock)


def read_response(sock: socket.socket) -> str:
    data = b""
    sock.settimeout(TIMEOUT)
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode("utf-8", errors="replace")


def status_line(resp: str) -> str:
    return resp.splitlines()[0] if resp else "(brak odpowiedzi)"


def parse_www_authenticate(resp: str):
    """Zwraca ('Digest', {realm, nonce, qop?}) albo ('Basic', {}) albo (None, {})."""
    m = re.search(r"WWW-Authenticate:\s*(\S+)\s+(.*)", resp, re.IGNORECASE)
    if not m:
        return None, {}
    scheme = m.group(1)
    params = dict(re.findall(r'(\w+)="([^"]*)"', m.group(2)))
    return scheme, params


def digest_response(user: str, password: str, realm: str, nonce: str, method: str, uri: str):
    ha1 = hashlib.md5(f"{user}:{realm}:{password}".encode()).hexdigest()
    ha2 = hashlib.md5(f"{method}:{uri}".encode()).hexdigest()
    return hashlib.md5(f"{ha1}:{nonce}:{ha2}".encode()).hexdigest()


def probe_one(host: str, port: int, path: str, user: str, password: str):
    url = f"rtsp://{host}:{port}{path}"
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((host, port))
    except OSError as e:
        return url, f"błąd połączenia: {e}", None

    try:
        resp = rtsp_request(sock, "DESCRIBE", url, 1, ["Accept: application/sdp"])
        line = status_line(resp)

        if " 401 " in line:
            scheme, params = parse_www_authenticate(resp)
            if scheme and scheme.lower() == "digest" and "realm" in params and "nonce" in params:
                digest = digest_response(user, password, params["realm"], params["nonce"], "DESCRIBE", url)
                auth_header = (
                    f'Authorization: Digest username="{user}", realm="{params["realm"]}", '
                    f'nonce="{params["nonce"]}", uri="{url}", response="{digest}"'
                )
            else:
                userpass = base64.b64encode(f"{user}:{password}".encode()).decode()
                auth_header = f"Authorization: Basic {userpass}"
            resp2 = rtsp_request(sock, "DESCRIBE", url, 2, ["Accept: application/sdp", auth_header])
            line2 = status_line(resp2)
            return url, f"{line}  ->  ({scheme or 'Basic'} auth) {line2}", resp2
        return url, line, resp
    finally:
        sock.close()


def main():
    ap = argparse.ArgumentParser(description="Ustalenie formatu RTSP URL na rejestratorze XMEYE")
    ap.add_argument("--host", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--port", type=int, default=RTSP_PORT)
    ap.add_argument("--channels", default="4,5", help="lista kanałów do testu (domyślnie te z kamerą: 4,5)")
    args = ap.parse_args()

    channels = [int(c) for c in args.channels.split(",")]
    paths = build_paths(args.user, args.password, channels)

    print(f"=== Test {len(paths)} kandydackich ścieżek RTSP na {args.host}:{args.port} ===\n")
    hits = []
    for ch, path in paths:
        url, result, full_resp = probe_one(args.host, args.port, path, args.user, args.password)
        ok = " 200 " in result
        marker = "OK " if ok else "   "
        print(f"[{marker}][ch{ch}] {result}")
        print(f"        {url}")
        if ok:
            hits.append((url, full_resp))

    print("\n=== Podsumowanie ===")
    if hits:
        print(f"{len(hits)} działający(ch) format(ów) — SDP z pierwszego trafienia:\n")
        print(hits[0][1])
    else:
        print("Żaden kandydat nie zwrócił 200. Kolejny krok: sniffing panelu web")
        print("(DevTools + tcpdump) albo Wireshark podczas ręcznego testu w kliencie RTSP —")
        print("patrz PROTOCOL_NOTES.md in the ha-xmeye-nvr repo, sekcja 'Ścieżka rozpoznania bez appki'.")


if __name__ == "__main__":
    main()
