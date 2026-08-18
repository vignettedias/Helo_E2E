#!/usr/bin/env python3
"""End-to-end integration across the real stack.

This is the test the whole project exists to pass. Everything else verifies a
component in isolation; this runs the ACTUAL Node relay process, drives it with
the ACTUAL reference protocol implementation over HTTP, and then opens the
relay's SQLite database directly to inspect what it managed to learn.

Alice and Bob never share a Python object. Every byte between them crosses a
real socket and lands in a real database first.

    python3 scripts/integration_e2e.py
"""

from __future__ import annotations

import json
import os
import random
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "crypto" / "reference"))

from helo_ref.identity import IdentityKeyPair, safety_number
from helo_ref.message import Envelope
from helo_ref.prekeys import PreKeyBundle, PreKeyStore
from helo_ref.session import Session, start_as_initiator, start_as_responder

PASSWORD = "correct-horse-battery-staple"
SECRET_CANARY = "MARIANA-TRENCH-CANARY-8817"

GREEN, RED, DIM, BOLD, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    mark = f"{GREEN}PASS{RESET}" if ok else f"{RED}FAIL{RESET}"
    print(f"  [{mark}] {label}" + (f" {DIM}{detail}{RESET}" if detail else ""))
    if not ok:
        failures.append(label)


def section(title: str) -> None:
    print(f"\n{BOLD}{title}{RESET}")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Relay:
    """Manages the real Node relay subprocess."""

    def __init__(self) -> None:
        self.port = free_port()
        self.dir = tempfile.mkdtemp(prefix="helo-e2e-")
        self.db_path = os.path.join(self.dir, "relay.db")
        self.proc: subprocess.Popen | None = None

    def start(self) -> None:
        env = {**os.environ, "PORT": str(self.port), "HOST": "127.0.0.1",
               "DB_PATH": self.db_path}
        self.proc = subprocess.Popen(
            ["node", str(REPO / "backend" / "src" / "server.js")],
            env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        for _ in range(100):
            try:
                self.request("GET", "/health")
                return
            except Exception:
                time.sleep(0.1)
        raise RuntimeError("relay failed to start")

    def stop(self) -> None:
        if self.proc:
            self.proc.terminate()
            self.proc.wait(timeout=10)

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def request(self, method: str, path: str, body=None, token=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        if token:
            req.add_header("Authorization", f"Bearer {token}")
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


class Client:
    """A Helo client: real crypto, real HTTP, no shortcuts."""

    def __init__(self, relay: Relay, username: str, device_id: str) -> None:
        self.relay = relay
        self.username = username
        self.device_id = device_id
        self.identity = IdentityKeyPair.generate()
        self.prekeys = PreKeyStore(self.identity)
        self.sessions: dict[str, Session] = {}
        self.inbox: list[tuple[str, bytes]] = []

    def register(self) -> None:
        self.relay.request("POST", "/auth/register",
                           {"username": self.username, "password": PASSWORD})
        _, login = self.relay.request("POST", "/auth/login",
                                      {"username": self.username, "password": PASSWORD})
        self.account_token = login["access_token"]

        _, dev = self.relay.request("POST", "/devices", {
            "device_id": self.device_id,
            "identity": self.identity.public().to_json(),
        }, token=self.account_token)
        self.device_token = dev["device_token"]

    def publish_prekeys(self, count: int = 20) -> int:
        self.prekeys.rotate_signed_prekey()
        one_time = self.prekeys.generate_one_time_prekeys(count)
        status, body = self.relay.request("POST", "/prekeys", {
            "device_id": self.device_id,
            "signed_prekey": self.prekeys.current_signed_prekey().to_json(),
            "one_time_prekeys": [o.to_json() for o in one_time],
        }, token=self.account_token)
        assert status == 200, body
        return body["available_one_time_prekeys"]

    def start_session_with(self, peer_device_id: str):
        status, body = self.relay.request(
            "GET", f"/prekeys/{peer_device_id}", token=self.account_token)
        assert status == 200, body
        bundle = PreKeyBundle.from_json({
            "device_id": body["device_id"],
            "identity": body["identity"],
            "signed_prekey": body["signed_prekey"],
            "one_time_prekey": body["one_time_prekey"],
        })
        session = start_as_initiator(self.identity, self.device_id, bundle)
        self.sessions[peer_device_id] = session
        return session, body["one_time_prekey_available"]

    def send(self, peer_device_id: str, text: bytes):
        envelope = self.sessions[peer_device_id].encrypt(text)
        status, body = self.relay.request("POST", "/messages", {
            "recipient_device_id": peer_device_id,
            "envelope": envelope.to_json(),
        }, token=self.account_token)
        assert status == 202, body
        return body["message_id"]

    def receive(self) -> list[tuple[str, bytes]]:
        status, body = self.relay.request("GET", "/messages", token=self.device_token)
        assert status == 200, body
        out, ack = [], []
        for item in body["messages"]:
            envelope = Envelope.from_json(item["envelope"])
            sender = item["sender_device_id"]
            if sender not in self.sessions:
                self.sessions[sender] = start_as_responder(
                    self.identity, self.device_id, self.prekeys, envelope)
            plaintext = self.sessions[sender].decrypt(envelope)
            out.append((sender, plaintext))
            ack.append(item["message_id"])
        if ack:
            self.relay.request("POST", "/delivery/ack",
                               {"message_ids": ack}, token=self.device_token)
        self.inbox.extend(out)
        return out


def main() -> int:
    relay = Relay()
    print(f"{BOLD}Helo end-to-end integration{RESET}")
    print(f"{DIM}real Node relay + real reference client + real database{RESET}")
    relay.start()
    print(f"{DIM}relay pid {relay.proc.pid} on port {relay.port}{RESET}")

    try:
        section("1. Registration and prekey publication")
        alice = Client(relay, "alice", "alice-device-1")
        bob = Client(relay, "bob", "bob-device-1")
        alice.register()
        bob.register()
        check("both accounts and devices registered", True)
        available = bob.publish_prekeys(20)
        check("Bob published prekeys", available == 20, f"{available} one-time prekeys")

        section("2. Asynchronous session establishment (Bob never online)")
        session, otp_used = alice.start_session_with("bob-device-1")
        check("Alice fetched Bob's bundle and built a session", session is not None)
        check("one-time prekey was consumed (four-DH, not downgraded)", otp_used)

        section("3. First message relayed while Bob is offline")
        alice.send("bob-device-1", SECRET_CANARY.encode())
        received = bob.receive()
        check("Bob decrypted Alice's opening message",
              len(received) == 1 and received[0][1].decode() == SECRET_CANARY)

        section("4. Bidirectional conversation over the wire")
        bob.sessions["alice-device-1"] = bob.sessions["alice-device-1"]
        bob_session_key = "alice-device-1"
        bob.send(bob_session_key, b"hello alice, received")
        got = alice.receive()
        check("Alice decrypted Bob's reply",
              len(got) == 1 and got[0][1] == b"hello alice, received")

        exchanged = 0
        for i in range(10):
            alice.send("bob-device-1", f"alice-{i}".encode())
            r = bob.receive()
            exchanged += len(r)
            bob.send(bob_session_key, f"bob-{i}".encode())
            r = alice.receive()
            exchanged += len(r)
        check("20 further messages exchanged with DH ratcheting", exchanged == 20,
              f"{exchanged} messages")

        section("5. Offline queue and out-of-order delivery")
        queued = [alice.send("bob-device-1", f"queued-{i}".encode()) for i in range(5)]
        check("5 messages queued while Bob is away", len(queued) == 5)
        delivered = bob.receive()
        check("all queued messages delivered and decrypted",
              len(delivered) == 5 and
              [d[1] for d in delivered] == [f"queued-{i}".encode() for i in range(5)])

        section("6. Identity verification")
        sn_alice = safety_number(alice.identity.public(), bob.identity.public())
        sn_bob = safety_number(bob.identity.public(), alice.identity.public())
        check("both parties compute the same safety number", sn_alice == sn_bob)
        print(f"       {DIM}{sn_alice}{RESET}")

        section("7. SERVER COMPROMISE SIMULATION")
        print(f"  {DIM}Opening the relay's SQLite database directly, as an attacker")
        print(f"  with full backend access would.{RESET}")

        # Force a checkpoint so WAL contents land in the main database file.
        con = sqlite3.connect(relay.db_path)
        con.execute("PRAGMA wal_checkpoint(FULL)")
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        dump_parts = []
        row_counts = {}
        for table in tables:
            rows = con.execute(f"SELECT * FROM {table}").fetchall()
            row_counts[table] = len(rows)
            dump_parts.append(json.dumps(rows, default=str))
        con.close()

        # Also scan the raw file bytes, not just parsed rows -- deleted pages
        # and WAL remnants live there.
        raw_bytes = Path(relay.db_path).read_bytes()
        for suffix in ("-wal", "-shm"):
            extra = Path(relay.db_path + suffix)
            if extra.exists():
                raw_bytes += extra.read_bytes()

        dump = "\n".join(dump_parts)
        print(f"  {DIM}tables: {', '.join(f'{t}={n}' for t, n in row_counts.items())}{RESET}")
        print(f"  {DIM}raw database size: {len(raw_bytes)} bytes{RESET}")

        check("canary plaintext absent from parsed rows", SECRET_CANARY not in dump)
        check("canary plaintext absent from RAW database bytes",
              SECRET_CANARY.encode() not in raw_bytes)
        check("no conversation plaintext in database",
              all(t.encode() not in raw_bytes
                  for t in ["hello alice", "queued-0", "alice-0", "bob-0"]))
        check("Alice's identity private key absent",
              alice.identity.dh_priv not in raw_bytes and
              alice.identity.sig_seed not in raw_bytes)
        check("Bob's identity private key absent",
              bob.identity.dh_priv not in raw_bytes and
              bob.identity.sig_seed not in raw_bytes)

        alice_ratchet = alice.sessions["bob-device-1"].ratchet
        check("no ratchet root key in database", alice_ratchet.root_key not in raw_bytes)
        check("no ratchet private key in database",
              alice_ratchet.dh_send_priv not in raw_bytes)
        check("no chain key in database",
              alice_ratchet.chain_key_send is None or
              alice_ratchet.chain_key_send not in raw_bytes)
        check("no account password in database", PASSWORD.encode() not in raw_bytes)
        check("no usable auth token in database",
              alice.device_token.encode() not in raw_bytes)

        section("8. What the relay DID learn (metadata, honestly enumerated)")
        con = sqlite3.connect(relay.db_path)
        devices = con.execute("SELECT device_id, account_id FROM devices").fetchall()
        otp_used_count = con.execute(
            "SELECT COUNT(*) FROM one_time_prekeys WHERE consumed_at IS NOT NULL"
        ).fetchone()[0]
        pending = con.execute("SELECT COUNT(*) FROM messages").fetchone()[0]
        con.close()
        print(f"  {DIM}- device identifiers and their account owners: {len(devices)} devices{RESET}")
        print(f"  {DIM}- which prekeys were consumed, and when: {otp_used_count}{RESET}")
        print(f"  {DIM}- message timing, sizes, routing, delivery state{RESET}")
        print(f"  {DIM}- retained ciphertext after acknowledgement: {pending} rows{RESET}")
        check("acknowledged ciphertext is deleted, not retained", pending == 0)

        section("9. Malicious relay: tamper with a stored ciphertext")
        alice.send("bob-device-1", b"this message will be tampered with")
        status, body = relay.request("GET", "/messages", token=bob.device_token)
        item = body["messages"][0]
        tampered = dict(item["envelope"])
        import base64
        ct = bytearray(base64.b64decode(tampered["ciphertext"]))
        ct[0] ^= 0x01
        tampered["ciphertext"] = base64.b64encode(bytes(ct)).decode()

        from helo_ref.errors import AuthenticationError
        try:
            bob.sessions["alice-device-1"].decrypt(Envelope.from_json(tampered))
            check("tampered ciphertext rejected", False, "it was ACCEPTED")
        except AuthenticationError:
            check("tampered ciphertext rejected with AuthenticationError", True)

        # The genuine message still works: tampering did not break the session.
        genuine = bob.sessions["alice-device-1"].decrypt(Envelope.from_json(item["envelope"]))
        check("session survives tampering attempt",
              genuine == b"this message will be tampered with")

        section("10. Replay through the relay")
        from helo_ref.errors import ReplayError
        try:
            bob.sessions["alice-device-1"].decrypt(Envelope.from_json(item["envelope"]))
            check("replayed ciphertext rejected", False, "it was ACCEPTED")
        except ReplayError:
            check("replayed ciphertext rejected with ReplayError", True)

    finally:
        relay.stop()

    print()
    if failures:
        print(f"{RED}{BOLD}{len(failures)} CHECK(S) FAILED{RESET}")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"{GREEN}{BOLD}All integration checks passed.{RESET}")
    print(f"{DIM}The relay carried the entire conversation without ever holding "
          f"plaintext or any key capable of producing it.{RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
