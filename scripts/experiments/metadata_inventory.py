#!/usr/bin/env python3
"""Experiment E3 — what the relay's database reveals (metadata inventory).

Runs the REAL relay, carries a small three-person conversation with the
reference client, and then reads the relay's SQLite file directly — the
position of an attacker who has stolen a backup or controls the server.

Records:
  1. every table and column, with the classification written next to it in
     backend/src/db.js (columns without one are reported as UNCLASSIFIED);
  2. the communication graph an attacker can rebuild from the messages table
     while messages are queued (sender device -> recipient device -> account,
     with timestamps and sizes; sampled right after each send, i.e. what a
     live observer of the database sees), and what is left after delivery;
  3. the distinct ciphertext sizes the relay stored for the same messages
     sent unpadded vs. with the default block-256 padding.

    python scripts/experiments/metadata_inventory.py
"""

from __future__ import annotations

import json
import re
import sqlite3
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "crypto" / "reference"))
sys.path.insert(0, str(REPO / "scripts"))

from helo_ref.padding import POLICIES, pad, unpad
from integration_e2e import Client, Relay

OUT = REPO / "research" / "results" / "metadata_inventory.json"

MESSAGES = [  # (from, to, text) — lengths deliberately varied
    ("alice", "bob", "hi"),
    ("alice", "bob", "are we still on for the network lab at 3?"),
    ("bob", "alice", "yes"),
    ("bob", "alice", "bringing the router config and the packet captures from last week, "
                     "plus the notes on the TCP retransmission experiment"),
    ("alice", "carol", "ok"),
    ("carol", "alice", "can you send me the slides?"),
]


def schema_classification() -> dict[str, dict[str, str]]:
    """Parse `-- TAG` comments from the CREATE TABLE statements in db.js."""
    src = (REPO / "backend" / "src" / "db.js").read_text(encoding="utf-8")
    tables: dict[str, dict[str, str]] = {}
    for m in re.finditer(r"CREATE TABLE IF NOT EXISTS (\w+) \((.*?)\n\);", src, re.S):
        cols = {}
        for line in m.group(2).splitlines():
            line = line.strip()
            cm = re.match(r"(\w+)\s+(TEXT|INTEGER|BLOB)", line)
            if not cm or cm.group(1).upper() in ("PRIMARY", "UNIQUE"):
                continue
            tag = re.search(r"--\s*([A-Z]+)", line)
            cols[cm.group(1)] = tag.group(1) if tag else "UNCLASSIFIED"
        tables[m.group(1)] = cols
    return tables


def graph(db: Path) -> dict:
    con = sqlite3.connect(db)
    try:
        owner = dict(con.execute(
            "SELECT d.device_id, a.username FROM devices d JOIN accounts a USING(account_id)"))
        rows = con.execute(
            "SELECT sender_device, recipient_device, size_bytes, queued_at, delivered_at FROM messages "
            "ORDER BY seq").fetchall()
        counts = {name: con.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                  for (name,) in con.execute(
                      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
    finally:
        con.close()
    edges: dict[str, int] = {}
    for s, r, *_ in rows:
        key = f"{owner.get(s, s)} -> {owner.get(r, r)}"
        edges[key] = edges.get(key, 0) + 1
    return {"rows": len(rows), "edges": edges,
            "sizes": [r[2] for r in rows],
            "has_timestamps": all(r[3] for r in rows),
            "table_rows": counts}


def last_row(db: Path) -> tuple:
    """The newest queued message as the relay holds it, joined to accounts."""
    con = sqlite3.connect(db)
    try:
        return con.execute(
            "SELECT sa.username, ra.username, m.size_bytes, m.queued_at FROM messages m "
            "JOIN devices sd ON sd.device_id = m.sender_device JOIN accounts sa ON sa.account_id = sd.account_id "
            "JOIN devices rd ON rd.device_id = m.recipient_device "
            "JOIN accounts ra ON ra.account_id = rd.account_id ORDER BY m.seq DESC LIMIT 1").fetchone()
    finally:
        con.close()


def observed(rows: list[tuple], table_rows: dict) -> dict:
    edges: dict[str, int] = {}
    for s, r, *_ in rows:
        edges[f"{s} -> {r}"] = edges.get(f"{s} -> {r}", 0) + 1
    return {"rows": len(rows), "edges": edges, "sizes": [r[2] for r in rows],
            "has_timestamps": all(r[3] for r in rows), "table_rows": table_rows}


def run(policy_name: str) -> dict:
    policy = POLICIES[policy_name]
    relay = Relay()
    relay.start()
    try:
        users = {n: Client(relay, n, f"{n}-device") for n in ("alice", "bob", "carol")}
        for c in users.values():
            c.register()
            c.publish_prekeys()
        received: dict[str, list[str]] = {n: [] for n in users}

        def drain(name: str) -> None:
            received[name] += [unpad(p).decode() for _, p in users[name].receive()]

        snapshots = []
        for frm, to, text in MESSAGES:
            # Conversational order: read before replying. (The minimal client
            # keeps one session per peer; simultaneous initiation is handled
            # by the app's Messenger and tested there, not here.)
            drain(frm)
            sender = users[frm]
            peer = f"{to}-device"
            if peer not in sender.sessions:
                sender.start_session_with(peer)
            sender.send(peer, pad(text.encode(), policy))
            snapshots.append(last_row(Path(relay.db_path)))
        for n in users:
            drain(n)
        after = graph(Path(relay.db_path))
        queued = observed(snapshots, after["table_rows"])
    finally:
        relay.stop()
    expected = {n: [t for f, to, t in MESSAGES if to == n] for n in users}
    return {"policy": policy_name, "queued": queued, "after_delivery": after,
            "all_delivered_and_decrypted": received == expected}


def main() -> int:
    schema = schema_classification()
    runs = {p: run(p) for p in ("none", "block-256")}
    tally: dict[str, int] = {}
    for cols in schema.values():
        for tag in cols.values():
            tally[tag] = tally.get(tag, 0) + 1
    results = {"experiment": "E3 relay metadata inventory", "messages": len(MESSAGES),
               "schema": schema, "column_classes": tally, "runs": runs}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")

    print("column classes:", ", ".join(f"{k}={v}" for k, v in sorted(tally.items())))
    for name, r in runs.items():
        q, a = r["queued"], r["after_delivery"]
        print(f"\n[{name}] delivered+decrypted: {r['all_delivered_and_decrypted']}")
        print(f"  observed while queued: {q['rows']} messages; graph: {q['edges']}")
        print(f"  stored sizes: {q['sizes']} -> {len(set(q['sizes']))} distinct")
        print(f"  after delivery: {a['rows']} message rows; graph: {a['edges']}")
    print(f"\nwrote {OUT.relative_to(REPO)}")
    return 0 if all(r["all_delivered_and_decrypted"] for r in runs.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
