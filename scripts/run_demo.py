#!/usr/bin/env python3
"""Run the Helo web demo locally: the real relay plus the Flutter web client.

    python scripts/run_demo.py            # serve an existing build
    python scripts/run_demo.py --build    # run `flutter build web` first
    python scripts/run_demo.py --fresh    # start from an empty relay database

The web client is served on TWO ports (default 5000 and 5001). Each port is a
separate browser origin, so each gets its own key storage: open one tab per
user and Alice and Bob are genuinely different devices, in one browser.

The relay is started with a CORS allowlist containing exactly those origins.
CORS is off in every other configuration; see RUNNING.md.

Standard library only. This is a development convenience, not a deployment:
the relay speaks plain HTTP here, which is acceptable only on localhost.
"""

from __future__ import annotations

import argparse
import functools
import http.server
import json
import os
import shutil
import signal
import socket
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
                        help="listen on all interfaces so phones on the same network can join")
    parser.add_argument("--build", action="store_true", help="run `flutter build web` first")
    parser.add_argument("--fresh", action="store_true", help="delete the demo relay database first")
    args = parser.parse_args()

    if os.name == "nt":
        os.system("")  # enable ANSI colours in the Windows console

    if args.build:
        build_web()
    if not (WEB_BUILD / "index.html").exists():
        sys.exit("No web build found. Run with --build, or: cd mobile && flutter build web")
    node = shutil.which("node")
    if not node:
        sys.exit("node not found on PATH (Node 22.5+ is required for node:sqlite).")

    ports = [int(p) for p in args.ports.split(",") if p.strip()]
    bind = "0.0.0.0" if args.lan else "127.0.0.1"
    for port in [args.relay_port, *ports]:
        if not port_free(bind, port):
            sys.exit(f"port {port} is already in use (another demo still running?)")

    hosts = ["localhost", "127.0.0.1"]
    lan = lan_address() if args.lan else None
    if lan:
        hosts.append(lan)
    origins = [f"http://{h}:{p}" for h in hosts for p in ports]

    DATA.mkdir(parents=True, exist_ok=True)
    db = DATA / "demo.db"
    if args.fresh:
        for suffix in ("", "-wal", "-shm"):
            Path(f"{db}{suffix}").unlink(missing_ok=True)
    log_path = DATA / "demo-relay.log"
    log_file = open(log_path, "a", encoding="utf-8")  # noqa: SIM115 - lives for the process

    relay = subprocess.Popen(
        [node, str(RELAY)],
        env={**os.environ, "PORT": str(args.relay_port), "HOST": bind,
             "DB_PATH": str(db), "CORS_ORIGINS": ",".join(origins)},
        stdout=log_file, stderr=subprocess.STDOUT,
    )
    if not wait_for_relay(args.relay_port):
        relay.terminate()
        sys.exit(f"relay failed to start; see {log_path}")

    handler = functools.partial(StaticHandler, directory=str(WEB_BUILD))
    servers = []
    for port in ports:
        server = http.server.ThreadingHTTPServer((bind, port), handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)

    users = ["Alice", "Bob", "Carol", "Dave", "Erin", "Frank"]
    print(f"\n{BOLD}Helo demo running{RESET}")
    print(f"  relay   http://127.0.0.1:{args.relay_port}  {DIM}(log: {log_path}){RESET}")
    for i, port in enumerate(ports):
        name = users[i] if i < len(users) else f"User {i + 1}"
        print(f"  {name:<7} {GREEN}http://localhost:{port}{RESET}")
        if lan:
            print(f"  {'':<7} {DIM}http://{lan}:{port}  (other devices on this network){RESET}")
    print(f"\n{DIM}Each port is a separate origin with its own keys. Register a user in each\n"
          f"tab, copy one device id into the other's New chat, and talk.{RESET}")
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
