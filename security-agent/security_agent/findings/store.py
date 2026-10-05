"""SQLite-backed findings + scans store with enforced lifecycle transitions."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from security_agent.findings.models import (
    Finding, State, VALID_TRANSITIONS, HUMAN_ONLY_TARGETS,
)


class FindingStore:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id   TEXT PRIMARY KEY,
                mode      TEXT,
                target    TEXT,
                model     TEXT,
                started_at TEXT,
                config    TEXT
            );
            CREATE TABLE IF NOT EXISTS findings (
                id         TEXT PRIMARY KEY,
                scan_id    TEXT,
                source     TEXT,
                target     TEXT,
                vuln_class TEXT,
                severity   TEXT,
                confidence TEXT,
                location   TEXT,
                description TEXT,
                poc        TEXT,
                remediation TEXT,
                state      TEXT,
                created_at TEXT,
                evidence   TEXT
            );
            CREATE TABLE IF NOT EXISTS transitions (
                finding_id TEXT,
                from_state TEXT,
                to_state   TEXT,
                actor      TEXT,
                ts         TEXT
            );
            """
        )
        self.conn.commit()

    # ---- scans ----------------------------------------------------------
    def create_scan(self, scan_id: str, mode: str, target: str, model: str, config: dict) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?)",
            (scan_id, mode, target, model,
             datetime.now(timezone.utc).isoformat(), json.dumps(config)),
        )
        self.conn.commit()

    # ---- findings -------------------------------------------------------
    def add_finding(self, f: Finding) -> None:
        r = f.to_row()
        self.conn.execute(
            """INSERT OR REPLACE INTO findings
               (id,scan_id,source,target,vuln_class,severity,confidence,location,
                description,poc,remediation,state,created_at,evidence)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (r["id"], r["scan_id"], r["source"], r["target"], r["vuln_class"],
             r["severity"], r["confidence"], r["location"], r["description"],
             r["poc"], r["remediation"], r["state"], r["created_at"],
             json.dumps(r["evidence"])),
        )
        self.conn.execute(
            "INSERT INTO transitions VALUES (?,?,?,?,?)",
            (r["id"], "", r["state"], "skill", datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def next_index(self, scan_id: str) -> int:
        cur = self.conn.execute("SELECT COUNT(*) AS n FROM findings WHERE scan_id=?", (scan_id,))
        return int(cur.fetchone()["n"]) + 1

    def get(self, finding_id: str) -> sqlite3.Row | None:
        cur = self.conn.execute("SELECT * FROM findings WHERE id=?", (finding_id,))
        return cur.fetchone()

    def list(self, scan_id: str | None = None, state: str | None = None) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings"
        clauses, params = [], []
        if scan_id:
            clauses.append("scan_id=?"); params.append(scan_id)
        if state:
            clauses.append("state=?"); params.append(state)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY created_at"
        return list(self.conn.execute(q, params))

    def annotate(self, finding_id: str, data: dict) -> None:
        """Merge `data` into a finding's evidence JSON (e.g. a validation verdict)."""
        row = self.get(finding_id)
        if row is None:
            raise KeyError(f"no such finding: {finding_id}")
        try:
            ev = json.loads(row["evidence"]) if row["evidence"] else {}
        except Exception:
            ev = {}
        ev.update(data)
        self.conn.execute("UPDATE findings SET evidence=? WHERE id=?",
                          (json.dumps(ev), finding_id))
        self.conn.commit()

    def transition(self, finding_id: str, to_state: State, actor: str) -> None:
        """Move a finding to a new state, enforcing the lifecycle rules.

        Human-only target states require actor='human'.
        """
        row = self.get(finding_id)
        if row is None:
            raise KeyError(f"no such finding: {finding_id}")
        current = State(row["state"])
        if to_state not in VALID_TRANSITIONS.get(current, set()):
            raise ValueError(f"illegal transition {current.value} -> {to_state.value}")
        if to_state in HUMAN_ONLY_TARGETS and actor != "human":
            raise PermissionError(
                f"{to_state.value} can only be set by an explicit human action"
            )
        self.conn.execute("UPDATE findings SET state=? WHERE id=?", (to_state.value, finding_id))
        self.conn.execute(
            "INSERT INTO transitions VALUES (?,?,?,?,?)",
            (finding_id, current.value, to_state.value, actor,
             datetime.now(timezone.utc).isoformat()),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()
