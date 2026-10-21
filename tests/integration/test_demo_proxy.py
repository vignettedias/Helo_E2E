"""The HTTPS demo proxy (`run_demo.py --lan`) in front of the REAL relay.

Regression for "photos, videos and voice messages fail with a validation
relay error" (2026-10-21): the proxy forwarded only an allowlist of request
headers and dropped `X-Helo-Recipients`, so every attachment upload reached
the relay without its recipient list and was (correctly) rejected with 400.
Text messages need no such header, which is why only media failed.

Every request here goes through the proxy exactly as a browser on the LAN or
in Termux would send it. Skipped when Node is not installed.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "scripts"))

import integration_e2e as e2e
import run_demo
from helo_ref import attachment

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="node (the relay) is not installed")
UNVERIFIED = ssl._create_unverified_context()  # the demo certificate is self-signed (test only)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class ProxiedRelay(e2e.Relay):
    """integration_e2e's client transport, pointed at the HTTPS proxy."""

    def __init__(self, base: str) -> None:
        self._base = base

    @property
    def base(self) -> str:
        return self._base

    def request(self, method, path, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self._base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=30, context=UNVERIFIED) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


@pytest.fixture(scope="module")
def demo():
    tmp = Path(tempfile.mkdtemp(prefix="helo-proxy-"))
    relay_port = _free_port()
    db = tmp / "relay.db"
    relay = subprocess.Popen(
        [NODE, str(REPO / "backend" / "src" / "server.js")],
        env={**os.environ, "PORT": str(relay_port), "HOST": "127.0.0.1", "DB_PATH": str(db),
             "TRUST_PROXY_LOOPBACK": "1"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    assert run_demo.wait_for_relay(relay_port), "relay did not start"

    web = tmp / "web"
    web.mkdir()
    (web / "index.html").write_text("<!doctype html><title>helo</title>flutter")
    run_demo.ProxyingHandler.relay_port = relay_port
    cert, key = run_demo.demo_certificate(["localhost", "127.0.0.1"], tmp / "tls")
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    server = run_demo.QuietHTTPServer(
        ("127.0.0.1", 0), functools.partial(run_demo.ProxyingHandler, directory=str(web)))
    server.socket = tls.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = f"https://127.0.0.1:{server.server_address[1]}"

    alice = e2e.Client(ProxiedRelay(base), "alice", "alice-device")
    bob = e2e.Client(ProxiedRelay(base), "bob", "bob-device")
    for c in (alice, bob):
        c.register()
        c.publish_prekeys()
    yield {"base": base, "alice": alice, "bob": bob, "db": db}

    server.shutdown()
    relay.terminate()
    relay.wait(timeout=10)
    shutil.rmtree(tmp, ignore_errors=True)


def _raw(base, method, path, *, body=None, headers=None):
    req = urllib.request.Request(base + path, data=body, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=60, context=UNVERIFIED) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _upload(demo, ciphertext: bytes, recipients: str | None, content_type="application/octet-stream"):
    headers = {"Authorization": f"Bearer {demo['alice'].device_token}", "Content-Type": content_type}
    if recipients is not None:
        headers["X-Helo-Recipients"] = recipients
    return _raw(demo["base"], "POST", "/attachments", body=ciphertext, headers=headers)


# Image-, video- and voice-sized payloads: the relay sees only ciphertext, so
# what matters is that bytes of every realistic size pass through intact.
MEDIA = {
    "photo.jpg (small image)": bytes((i * 31 + 7) % 256 for i in range(48_000)),
    "clip.mp4 (video, 6 MB)": os.urandom(6 * 1024 * 1024),
    "voice.wav (audio)": b"RIFF" + bytes(160_000),
}


@pytest.mark.parametrize("name", list(MEDIA))
def test_encrypted_media_upload_through_the_proxy_reaches_the_recipient(demo, name):
    plaintext = MEDIA[name]
    key = attachment.generate_key()
    ct = attachment.encrypt(key, plaintext)

    status, body = _upload(demo, ct, "alice-device,bob-device")
    assert status == 201, (status, body[:200])
    att_id = json.loads(body)["attachment_id"]

    # The recipient downloads through the proxy, checks the digest, decrypts.
    status, fetched = _raw(demo["base"], "GET", f"/attachments/{att_id}",
                           headers={"Authorization": f"Bearer {demo['bob'].device_token}"})
    assert status == 200
    assert attachment.digest(fetched) == attachment.digest(ct)
    assert attachment.decrypt(key, fetched) == plaintext

    # The relay stored ciphertext, never the media or its key.
    with sqlite3.connect(demo["db"]) as con:
        stored = con.execute("SELECT data FROM attachments WHERE attachment_id = ?", (att_id,)).fetchone()[0]
    assert stored == ct
    assert plaintext[:4096] not in stored
    assert key not in stored


def test_a_device_not_listed_cannot_download(demo):
    ct = attachment.encrypt(attachment.generate_key(), b"only for alice")
    status, body = _upload(demo, ct, "alice-device")
    assert status == 201
    att_id = json.loads(body)["attachment_id"]
    status, _ = _raw(demo["base"], "GET", f"/attachments/{att_id}",
                     headers={"Authorization": f"Bearer {demo['bob'].device_token}"})
    assert status == 404


@pytest.mark.parametrize(("recipients", "content_type", "body", "expected"), [
    (None, "application/octet-stream", b"x" * 64, (400, "x-helo-recipients")),
    ("", "application/octet-stream", b"x" * 64, (400, "x-helo-recipients")),
    ("bob device!", "application/octet-stream", b"x" * 64, (400, "x-helo-recipients")),
    ("bob-device", "application/octet-stream", b"", (400, "body")),
    ("bob-device", "application/json", b"{}", (415, None)),
])
def test_validation_still_applies_and_its_reason_reaches_the_client(demo, recipients, content_type, body,
                                                                      expected):
    status, raw = _upload(demo, body, recipients, content_type)
    err = json.loads(raw)
    assert status == expected[0]
    if expected[1] is not None:
        assert err == {"error": "validation_failed", "field": expected[1], "message": err["message"]}


def test_oversized_upload_is_refused(demo):
    # The relay limit is 25 MiB; just over it is refused by the relay, and far
    # over it by the proxy itself (without reading the body). Neither is stored.
    status, raw = _upload(demo, b"\0" * (26 * 1024 * 1024), "bob-device")
    assert status == 413, (status, raw[:200])


def test_text_messages_still_flow_through_the_proxy(demo):
    alice, bob = demo["alice"], demo["bob"]
    if "bob-device" not in alice.sessions:
        alice.start_session_with("bob-device")
    alice.send("bob-device", b"text works")
    assert (("alice-device", b"text works")) in bob.receive()


def test_proxy_forwards_exactly_the_headers_the_relay_api_uses():
    # Every request header the client sends to the relay must be forwarded;
    # nothing else is (no cookies, no hop-by-hop headers).
    assert set(run_demo.FORWARD_REQUEST_HEADERS) == {
        "authorization", "content-type", "accept", "last-event-id", "x-helo-recipients"}


def test_proxy_refuses_a_huge_declared_body_without_reading_it(demo):
    import http.client

    host, port = demo["base"].removeprefix("https://").split(":")
    conn = http.client.HTTPSConnection(host, int(port), timeout=10, context=UNVERIFIED)
    conn.putrequest("POST", "/attachments")
    conn.putheader("Content-Type", "application/octet-stream")
    conn.putheader("Content-Length", str(run_demo.MAX_PROXIED_BODY + 1))
    conn.endheaders()  # no body is ever sent: the proxy must answer anyway
    resp = conn.getresponse()
    assert resp.status == 413
    assert json.loads(resp.read()) == {"error": "payload_too_large"}
    conn.close()
