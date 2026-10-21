#!/usr/bin/env python3
"""Run the Helo web demo locally: the real relay plus the Flutter web client.

    python scripts/run_demo.py            # serve an existing build
    python scripts/run_demo.py --build    # run `flutter build web` first
    python scripts/run_demo.py --fresh    # start from an empty relay database
    python scripts/run_demo.py --lan      # HTTPS on this Wi-Fi, so a phone can join

The web client is served on TWO ports (default 5000 and 5001). Each port is a
separate browser origin, so each gets its own key storage: open one tab per
user and Alice and Bob are genuinely different devices, in one browser.

The relay is started with a CORS allowlist containing exactly those origins.
CORS is off in every other configuration; see RUNNING.md.

--lan serves the app over HTTPS with a self-signed certificate made for this
machine's LAN address, and forwards the relay API on the same origin, so the
relay itself still listens on 127.0.0.1 only. Browsers allow the key store,
camera and microphone only on https:// (or localhost), which is why plain HTTP
on a LAN address cannot work. The phone shows a certificate warning once; that
is expected for a self-signed demo certificate and is NOT acceptable for a real
deployment (use a real certificate, see docker/).

Standard library plus `cryptography` (already needed by the reference
implementation) for the --lan certificate. This is a development convenience,
not a deployment.
"""

from __future__ import annotations

import argparse
import datetime as dt
import functools
import http.client
import http.server
import ipaddress
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path
from typing import ClassVar

REPO = Path(__file__).resolve().parents[1]
WEB_BUILD = REPO / "mobile" / "build" / "web"
RELAY = REPO / "backend" / "src" / "server.js"
DATA = REPO / "backend" / "data"
# Written by scripts/verify.py; the app's Verification dashboard fetches it.
REPORT = REPO / "reports" / "verification.json"

GREEN, YELLOW, DIM, BOLD, RESET = "\033[32m", "\033[33m", "\033[2m", "\033[1m", "\033[0m"


class StaticHandler(http.server.SimpleHTTPRequestHandler):
    """Serves the web build with correct MIME types and no caching.

    Python's mimetypes reads the Windows registry, where .js is sometimes
    mapped to text/plain; pin the types the Flutter loader depends on.
    """

    extensions_map: ClassVar[dict[str, str]] = {
        **http.server.SimpleHTTPRequestHandler.extensions_map,
        ".js": "text/javascript",
        ".mjs": "text/javascript",
        ".wasm": "application/wasm",
        ".json": "application/json",
        ".html": "text/html; charset=utf-8",
    }

    def end_headers(self) -> None:
        # No caching, so a rebuild is picked up on reload.
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        super().end_headers()

    def log_message(self, format: str, *args) -> None:
        pass  # keep the console readable; the relay log is written to a file

    def do_GET(self) -> None:
        # The verification report lives outside the web build (it is produced
        # by scripts/verify.py, not by flutter build), so serve it explicitly.
        if self.path.split("?", 1)[0] == "/verification.json":
            if not REPORT.is_file():
                self.send_error(404, "No report yet: run python scripts/verify.py")
                return
            body = REPORT.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


# First path segments that belong to the relay API (backend/src/routes/*.js).
RELAY_PREFIXES = frozenset({
    "auth", "devices", "prekeys", "users", "presence", "messages", "delivery",
    "attachments", "me", "reports", "health",
})
# Every request header the client sends to the relay API, and nothing else
# (no cookies, no hop-by-hop headers). X-Helo-Recipients carries the device ids
# allowed to download an attachment: dropping it made every media upload fail
# with 400 validation_failed (see tests/integration/test_demo_proxy.py).
FORWARD_REQUEST_HEADERS = ("authorization", "content-type", "accept", "last-event-id",
                           "x-helo-recipients")
# The proxy reads a request body whole before forwarding it, so it enforces a
# cap of its own: the relay's attachment limit (25 MiB) plus room for headers
# of a JSON request. Larger bodies are refused here with 413, unread.
MAX_PROXIED_BODY = 26 * 1024 * 1024
_HOP_BY_HOP = frozenset({"connection", "keep-alive", "transfer-encoding", "te", "trailer",
                         "upgrade", "proxy-authenticate", "proxy-authorization"})


class ProxyingHandler(StaticHandler):
    """--lan: static files plus the relay API on the SAME https origin.

    Same origin means no mixed content and no CORS. The real client address is
    passed in X-Forwarded-For, which the relay honours only from loopback and
    only with TRUST_PROXY_LOOPBACK=1 (so rate limits stay per device).
    """

    relay_port: ClassVar[int] = 8443

    def _json_error(self, status: int, code: str) -> None:
        """An error in the relay's own format, so the client handles it the same way."""
        body = json.dumps({"error": code}).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _is_relay(self) -> bool:
        return self.path.split("?", 1)[0].strip("/").split("/", 1)[0] in RELAY_PREFIXES

    def _proxy(self) -> None:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self.send_error(400, "bad Content-Length")
            return
        if length < 0 or length > MAX_PROXIED_BODY:
            self.close_connection = True
            self._json_error(413, "payload_too_large")
            return
        body = self.rfile.read(length) if length else None
        headers = {k: v for k, v in self.headers.items() if k.lower() in FORWARD_REQUEST_HEADERS}
        headers["X-Forwarded-For"] = self.client_address[0]
        conn = http.client.HTTPConnection("127.0.0.1", self.relay_port, timeout=90)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
            self.send_response(resp.status)
            streaming = resp.getheader("Content-Length") is None
            for k, v in resp.getheaders():
                if k.lower() not in _HOP_BY_HOP:
                    self.send_header(k, v)
            if streaming:
                self.send_header("Connection", "close")
                self.close_connection = True
            self.end_headers()
            while True:
                chunk = resp.read1(65536) if streaming else resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                if streaming:
                    self.wfile.flush()
        except OSError:
            self.send_error(502, "relay unavailable")
        finally:
            conn.close()

    def do_GET(self) -> None:
        if self._is_relay():
            self._proxy()
        else:
            super().do_GET()

    def do_POST(self) -> None:
        self._proxy() if self._is_relay() else self.send_error(404)

    def do_PUT(self) -> None:
        self._proxy() if self._is_relay() else self.send_error(404)

    def do_DELETE(self) -> None:
        self._proxy() if self._is_relay() else self.send_error(404)


def demo_certificate(hosts: list[str], directory: Path) -> tuple[Path, Path]:
    """A self-signed certificate for exactly these names, reused while valid.

    Demo only: generated locally, never leaves this machine, valid 30 days.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    directory.mkdir(parents=True, exist_ok=True)
    cert_path, key_path, meta_path = directory / "cert.pem", directory / "key.pem", directory / "hosts.json"
    now = dt.datetime.now(dt.UTC)
    if cert_path.exists() and key_path.exists() and meta_path.exists():
        try:
            same = json.loads(meta_path.read_text()) == sorted(hosts)
            cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
            if same and cert.not_valid_after_utc > now + dt.timedelta(days=1):
                return cert_path, key_path
        except (ValueError, OSError):
            pass
    key = ec.generate_private_key(ec.SECP256R1())
    names: list[x509.GeneralName] = []
    for h in hosts:
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            names.append(x509.DNSName(h))
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Helo local demo")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                           serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    meta_path.write_text(json.dumps(sorted(hosts)))
    return cert_path, key_path


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    """Logs a one-line note instead of a traceback for expected TLS failures.

    A browser seeing the self-signed certificate for the first time closes the
    connection with "certificate unknown"; that is normal, not a server error.
    """

    def handle_error(self, request, client_address) -> None:
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionError, TimeoutError)):
            return
        super().handle_error(request, client_address)


def all_ipv4_addresses() -> list[str]:
    """Every non-loopback IPv4 address of this machine, default route first."""
    found: list[str] = []
    first = lan_address()
    if first:
        found.append(first)
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addr = info[4][0]
            if addr not in found and not addr.startswith("127."):
                found.append(addr)
    except OSError:
        pass
    return found


# Strings that only appear in main.dart.js when a plugin's WEB implementation
# was compiled in (i.e. registered). A build made with a stale
# .dart_tool/flutter_build/*/web_plugin_registrant.dart lacks them, and the app
# then falls back to native method channels that do not exist in a browser.
WEB_PLUGIN_MARKERS = {
    "file picker (photos, videos, files)": "__file_picker_web-file-input",
    "recorder (voice messages)": "record.worklet.js",
}


def missing_web_plugins(build: Path) -> list[str]:
    try:
        js = (build / "main.dart.js").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [name for name, marker in WEB_PLUGIN_MARKERS.items() if marker not in js]


def lan_address() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 80))  # TEST-NET-1: nothing is sent
            return s.getsockname()[0]
    except OSError:
        return None


def port_free(host: str, port: int) -> bool:
    with socket.socket() as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def build_web() -> None:
    flutter = shutil.which("flutter") or os.environ.get("FLUTTER")
    if not flutter:
        sys.exit("flutter not found on PATH (or set FLUTTER=path/to/flutter).")
    print(f"{DIM}building web client...{RESET}", flush=True)
    subprocess.run([flutter, "build", "web", "--release", "--no-wasm-dry-run"],
                   cwd=REPO / "mobile", check=True, shell=os.name == "nt")


def wait_for_relay(port: int, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1) as r:
                return json.load(r).get("status") == "ok"
        except OSError:
            time.sleep(0.2)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--ports", default="5000,5001",
                        help="comma-separated web ports, one per demo user (default 5000,5001)")
    parser.add_argument("--relay-port", type=int, default=8443)
    parser.add_argument("--lan", action="store_true",
                        help="serve over HTTPS on this network so a phone can join (self-signed)")
    parser.add_argument("--build", action="store_true", help="run `flutter build web` first")
    parser.add_argument("--fresh", action="store_true", help="delete the demo relay database first")
    args = parser.parse_args()

    if os.name == "nt":
        os.system("")  # enable ANSI colours in the Windows console

    if args.build:
        build_web()
    if not (WEB_BUILD / "index.html").exists():
        sys.exit("No web build found. Run with --build, or: cd mobile && flutter build web")
    missing = missing_web_plugins(WEB_BUILD)
    if missing:
        print(f"{YELLOW}{BOLD}This web build is missing plugin code: {', '.join(missing)}.{RESET}\n"
              f"{YELLOW}Photos, videos, files and voice messages will fail in the browser. The build used a\n"
              f"stale plugin registration; rebuild from clean:\n"
              f"    cd mobile && flutter clean && flutter pub get && flutter build web --release{RESET}\n",
              flush=True)
    node = shutil.which("node")
    if not node:
        sys.exit("node not found on PATH (Node 22.5+ is required for node:sqlite).")

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    bind = "0.0.0.0" if args.lan else "127.0.0.1"
    if not port_free("127.0.0.1", args.relay_port):
        sys.exit(f"port {args.relay_port} is already in use (another demo still running?)")
    for port in ports:
        if not port_free(bind, port):
            sys.exit(f"port {port} is already in use (another demo still running?)")

    hosts = ["localhost", "127.0.0.1"]
    lan_ips = all_ipv4_addresses() if args.lan else []
    if args.lan and not lan_ips:
        sys.exit("--lan: could not determine this machine's network address (is Wi-Fi connected?)")
    lan = lan_ips[0] if lan_ips else None
    hosts.extend(lan_ips)
    # --lan: the page and the API share one https origin, so no CORS is needed.
    origins = [] if args.lan else [f"http://{h}:{p}" for h in hosts for p in ports]

    DATA.mkdir(parents=True, exist_ok=True)
    db = DATA / "demo.db"
    if args.fresh:
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
    log_path = DATA / "demo-relay.log"
    log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 - lives for the process

    relay = subprocess.Popen(
        [node, str(RELAY)],
        # The relay always listens on loopback only; --lan reaches it through
        # the HTTPS proxy below.
        env={**os.environ, "PORT": str(args.relay_port), "HOST": "127.0.0.1",
             "DB_PATH": str(db), "CORS_ORIGINS": ",".join(origins),
             "TRUST_PROXY_LOOPBACK": "1" if args.lan else "0"},
        stdout=log_file, stderr=subprocess.STDOUT,
    )
    if not wait_for_relay(args.relay_port):
        relay.terminate()
        sys.exit(f"relay failed to start; see {log_path}")

    tls: ssl.SSLContext | None = None
    if args.lan:
        ProxyingHandler.relay_port = args.relay_port
        handler = functools.partial(ProxyingHandler, directory=str(WEB_BUILD))
        cert, key = demo_certificate(hosts, DATA / "demo-tls")
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_2
        tls.load_cert_chain(cert, key)
    else:
        handler = functools.partial(StaticHandler, directory=str(WEB_BUILD))
    servers = []
    for port in ports:
        server = QuietHTTPServer((bind, port), handler)
        if tls is not None:
            # Handshake in the request thread, so one slow client cannot stall accept().
            server.socket = tls.wrap_socket(server.socket, server_side=True,
                                            do_handshake_on_connect=False)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)

    users = ["Alice", "Bob", "Carol", "Dave", "Erin", "Frank"]
    print(f"\n{BOLD}Helo demo running{RESET}")
    print(f"  relay   http://127.0.0.1:{args.relay_port}  {DIM}(log: {log_path}){RESET}")
    scheme = "https" if args.lan else "http"
    for i, port in enumerate(ports):
        name = users[i] if i < len(users) else f"User {i + 1}"
        print(f"  {name:<7} {GREEN}{scheme}://localhost:{port}{RESET}")
        for ip in lan_ips:
            print(f"  {'':<7} {GREEN}https://{ip}:{port}{RESET}  {DIM}(phone / other devices on the same Wi-Fi){RESET}")
    print(f"\n{DIM}Each port is a separate origin with its own keys. Register a user in each\n"
          f"tab, then start a chat by username.{RESET}")
    if len(lan_ips) > 1:
        print(f"{DIM}Several network addresses: use the one shown under 'Wireless LAN adapter\n"
              f"Wi-Fi' in `ipconfig` (normally the first above). 192.168.56.x is usually\n"
              f"VirtualBox.{RESET}")
    if lan:
        print(f"{YELLOW}Self-signed demo certificate: each browser warns once. Choose\n"
              f"Advanced -> Proceed (Chrome) or Show Details -> visit (Safari). If the phone\n"
              f"cannot connect, allow Python through the Windows firewall on Private networks.{RESET}")
    if args.fresh:
        print(f"{YELLOW}Fresh relay database: clear site data in the browser too, or old tabs will\n"
              f"still hold identities this relay has never seen.{RESET}")
    print(f"{DIM}Ctrl+C to stop.{RESET}\n", flush=True)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.is_set() and relay.poll() is None:
            stop.wait(0.5)
    finally:
        for server in servers:
            server.shutdown()
        relay.terminate()
        try:
            relay.wait(timeout=10)
        except subprocess.TimeoutExpired:
            relay.kill()
        log_file.close()
    if relay.returncode not in (None, 0) and not stop.is_set():
        print(f"relay exited unexpectedly; see {log_path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
