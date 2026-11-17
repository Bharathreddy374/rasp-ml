"""Persistence. One interface, two implementations:

  PostgresStore  production. Everything a request produces is written in ONE transaction.
  MemoryStore    tests and `STORE=memory` development runs. Same behaviour, lost on restart.

A session is identified by (install_id, session_id), both chosen by the phone. Saving the
same pair twice raises Duplicate, so a client retry never creates a second row; the caller
then returns the stored result.
"""
import json
import re
import ssl
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qs, unquote, urlsplit

import pg8000.dbapi as pg

SCHEMA_SQL = Path(__file__).resolve().parent.parent / "db" / "schema.sql"


class Duplicate(Exception):
    """The (install_id, session_id) pair is already stored."""


class StoreError(Exception):
    """The database could not be reached or the statement failed."""


class Store(Protocol):
    def migrate(self) -> None: ...
    def ping(self) -> bool: ...
    def find(self, install_id: str, session_id: str) -> dict | None: ...
    def get(self, pk: str) -> dict | None: ...
    def lookup(self, install_id: str, net24: str | None, since: datetime, limit: int = 200) -> tuple[list[dict], int]: ...
    def save(self, session: dict, retrieved: dict, result: dict) -> str: ...
    def list_sessions(self, install_id: str | None, min_level: int | None, limit: int) -> list[dict]: ...
    def training_features(self, max_rules_level: int, limit: int) -> list[dict]: ...


# ---------------------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------------------
class PostgresStore:
    def __init__(self, url: str, schema: str = "public"):
        parsed = urlsplit(url)
        if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
            raise ValueError("DATABASE_URL must be a PostgreSQL connection string")
        if not re.fullmatch(r"[a-z_][a-z0-9_]{0,62}", schema):
            raise ValueError("DB_SCHEMA must be a lowercase identifier")
        self._kw = dict(
            user=unquote(parsed.username or ""), password=unquote(parsed.password or ""),
            host=parsed.hostname, port=parsed.port or 5432, database=parsed.path.lstrip("/"),
            ssl_context=ssl.create_default_context() if parse_qs(parsed.query).get("sslmode") else None,
            timeout=15,
        )
        self.schema = schema
        self._idle: list = []          # connections ready for reuse (opening one costs 1-2 s over TLS)
        self._lock = threading.Lock()
        self._max_idle = 4

    def _connect(self):
        try:
            conn = pg.connect(**self._kw)
            conn.autocommit = True       # every statement is its own transaction: no BEGIN/COMMIT round trips
            cur = conn.cursor()
            cur.execute(f'SET search_path TO "{self.schema}"')
            cur.close()
            return conn
        except Exception as exc:  # noqa: BLE001
            raise StoreError(f"database connection failed: {type(exc).__name__}") from exc

    def _acquire(self, fresh: bool = False):
        if not fresh:
            with self._lock:
                if self._idle:
                    return self._idle.pop()
        return self._connect()

    def _release(self, conn) -> None:
        with self._lock:
            if len(self._idle) < self._max_idle:
                self._idle.append(conn)
                return
        _close(conn)

    def _run(self, work, _retry: bool = True):
        """Run work(cursor) on a pooled autocommit connection. A write must therefore be ONE statement
        (see save()), which PostgreSQL executes atomically. If a reused connection turns out to be dead
        (the server closes idle connections), retry once on a fresh one. Retrying a write is safe
        because a session is unique per (install_id, session_id): a repeat becomes Duplicate.
        """
        conn = self._acquire(fresh=not _retry)
        try:
            cur = conn.cursor()
            try:
                out = work(cur)
            finally:
                cur.close()
        except (pg.InterfaceError, OSError) as exc:     # connection lost
            _close(conn)
            if _retry:
                return self._run(work, _retry=False)
            raise StoreError(f"database connection lost: {type(exc).__name__}") from exc
        except StoreError:
            _close(conn)
            raise
        except Exception as exc:  # noqa: BLE001
            code = _sqlstate(exc)
            self._release(conn)
            if code == "23505":          # unique_violation: this (install_id, session_id) exists
                raise Duplicate() from exc
            raise StoreError(f"database error ({code or type(exc).__name__}): {_message(exc)}") from exc
        self._release(conn)
        return out

    def migrate(self) -> None:
        sql = SCHEMA_SQL.read_text(encoding="utf-8")
        statements = [s.strip() for s in re.sub(r"--[^\n]*", "", sql).split(";") if s.strip()]

        def work(cur):
            if self.schema != "public":
                cur.execute(f'CREATE SCHEMA IF NOT EXISTS "{self.schema}"')
            for s in statements:
                cur.execute(s)
        self._run(work)

    def ping(self) -> bool:
        try:
            self._run(lambda cur: cur.execute("SELECT 1"))
            return True
        except StoreError:
            return False

    # ---- reads: one round trip each ----
    @staticmethod
    def _load(cur, where: str, args: tuple) -> dict | None:
        """One session with its retrievals and result, as nested JSON built by the database."""
        rows = _fetch(cur, f"""
            SELECT to_jsonb(s) AS session, to_jsonb(r) AS retrieved, to_jsonb(x) AS result
              FROM collect_sessions s
              LEFT JOIN session_retrievals r ON r.session_id = s.id
              LEFT JOIN session_results    x ON x.session_id = s.id
             WHERE {where}""", args)
        return rows[0] if rows else None

    def find(self, install_id: str, session_id: str) -> dict | None:
        return self._run(lambda cur: self._load(cur, "s.install_id = %s AND s.session_id = %s", (install_id, session_id)))

    def get(self, pk: str) -> dict | None:
        try:
            uuid.UUID(pk)
        except ValueError:
            return None
        return self._run(lambda cur: self._load(cur, "s.id = %s::uuid", (pk,)))

    def lookup(self, install_id: str, net24: str | None, since: datetime, limit: int = 200) -> tuple[list[dict], int]:
        """Everything the retrieval stage needs, in ONE query: this install's earlier sessions (newest
        first) and how many distinct installs used the same /24 network since `since`."""
        def work(cur):
            rows = _fetch(cur, """
                SELECT h.received_at, h.scan_time, h.client_ip, h.app_version, h.device,
                       h.final_level, h.reason_count, n.installs AS net_installs
                  FROM (SELECT count(DISTINCT install_id) AS installs FROM collect_sessions
                         WHERE net24 = %s AND received_at >= %s) n
                  LEFT JOIN (
                        SELECT s.received_at, s.scan_time, s.client_ip, s.app_version, s.device,
                               r.final_level, COALESCE(jsonb_array_length(r.reasons), 0) AS reason_count
                          FROM collect_sessions s LEFT JOIN session_results r ON r.session_id = s.id
                         WHERE s.install_id = %s ORDER BY s.received_at DESC LIMIT %s) h ON TRUE
                 ORDER BY h.received_at DESC NULLS LAST""", (net24, since, install_id, limit))
            installs = int(rows[0]["net_installs"]) if rows else 0
            return [_plain({k: v for k, v in r.items() if k != "net_installs"}) for r in rows
                    if r["received_at"] is not None], installs
        return self._run(work)

    def list_sessions(self, install_id, min_level, limit) -> list[dict]:
        where, args = ["TRUE"], []
        if install_id:
            where.append("s.install_id = %s")
            args.append(install_id)
        if min_level:
            where.append("r.final_level >= %s")
            args.append(min_level)
        args.append(limit)
        return self._run(lambda cur: [_plain(r) for r in _fetch(cur, f"""
            SELECT s.id, s.install_id, s.session_id, s.received_at, s.action,
                   r.final_level, r.risk_score, r.label, r.outcome, r.rules_level, r.ml_level, r.ml_status
              FROM collect_sessions s LEFT JOIN session_results r ON r.session_id = s.id
             WHERE {' AND '.join(where)} ORDER BY s.received_at DESC LIMIT %s""", tuple(args))])

    def training_features(self, max_rules_level: int, limit: int) -> list[dict]:
        return self._run(lambda cur: [_plain(r) for r in _fetch(cur, """
            SELECT features, rules_level FROM session_results
             WHERE rules_level <= %s ORDER BY scored_at DESC LIMIT %s""", (max_rules_level, limit))])

    # ---- write: ONE statement, so all three rows are stored or none are ----
    def save(self, session: dict, retrieved: dict, result: dict) -> str:
        """Insert the session, its retrievals and its result in a single data-modifying CTE. The
        connection is autocommit, so this one statement is the transaction, in one round trip.
        Raises Duplicate if (install_id, session_id) already exists."""
        pk = str(uuid.uuid4())
        self._run(lambda cur: cur.execute("""
            WITH s AS (
                INSERT INTO collect_sessions
                  (id, install_id, session_id, scan_time, action, client_ip, net24, user_agent,
                   payload_bytes, app_version, device, app, signals, unknown, failed_groups)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)
            ), r AS (
                INSERT INTO session_retrievals (session_id, server_signals, history, checks, retrieval_ms)
                VALUES (%s::uuid, %s::jsonb, %s::jsonb, %s::jsonb, %s)
            )
            INSERT INTO session_results
              (session_id, rules_level, ml_level, final_level, risk_score, label, outcome, assurance, ml_mode,
               ml_status, model_version, model_data, feature_coverage,
               reasons, features, ml, coverage, timings_ms)
            VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb)""",
            (pk, session["install_id"], session["session_id"], session["scan_time"], session["action"],
             session["client_ip"], session["net24"], session["user_agent"], session["payload_bytes"],
             session["app_version"], _j(session["device"]), _j(session["app"]), _j(session["signals"]),
             _j(session["unknown"]), _j(session["failed_groups"]),
             pk, _j(retrieved["server_signals"]), _j(retrieved["history"]), _j(retrieved["checks"]),
             retrieved["retrieval_ms"],
             pk, result["rules_level"], result["ml_level"], result["final_level"], result.get("risk_score"), result["label"],
             result["outcome"], result["assurance"], result["ml_mode"], result["ml_status"],
             result["model_version"], result["model_data"], result["feature_coverage"],
             _j(result["reasons"]), _j(result["features"]), _j(result["ml"]), _j(result["coverage"]),
             _j(result["timings_ms"]))))
        return pk


def _j(value) -> str:
    return json.dumps(value, default=str)


def _close(conn) -> None:
    try:
        conn.close()
    except Exception:  # noqa: BLE001
        pass


def _sqlstate(exc: Exception) -> str | None:
    """pg8000 puts the server's error fields in exc.args[0]; 'C' is the SQLSTATE."""
    info = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
    return info.get("C")


def _message(exc: Exception) -> str:
    info = exc.args[0] if exc.args and isinstance(exc.args[0], dict) else {}
    return str(info.get("M", exc))


def _fetch(cur, sql: str, args: tuple = ()) -> list[dict]:
    cur.execute(sql, args)
    if cur.description is None:
        return []
    names = [d[0] for d in cur.description]
    return [dict(zip(names, row)) for row in cur.fetchall()]


def _plain(row: dict) -> dict:
    """JSON-friendly copy: datetimes and UUIDs become strings."""
    out = {}
    for k, v in row.items():
        out[k] = v.isoformat() if isinstance(v, datetime) else str(v) if isinstance(v, uuid.UUID) else v
    return out


# ---------------------------------------------------------------------------------------
# In memory
# ---------------------------------------------------------------------------------------
class MemoryStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._rows: dict[str, dict] = {}
        self._keys: dict[tuple[str, str], str] = {}

    def migrate(self) -> None:
        pass

    def ping(self) -> bool:
        return True

    def find(self, install_id: str, session_id: str) -> dict | None:
        pk = self._keys.get((install_id, session_id))
        return self.get(pk) if pk else None

    def get(self, pk: str) -> dict | None:
        row = self._rows.get(pk)
        return json.loads(json.dumps(row, default=str)) if row else None

    def lookup(self, install_id: str, net24: str | None, since: datetime, limit: int = 200) -> tuple[list[dict], int]:
        with self._lock:
            rows = list(self._rows.values())
        mine = sorted((r for r in rows if r["session"]["install_id"] == install_id),
                      key=lambda r: r["session"]["received_at"], reverse=True)
        history = [{"received_at": r["session"]["received_at"].isoformat(), "scan_time": r["session"]["scan_time"].isoformat(),
                    "client_ip": r["session"]["client_ip"], "app_version": r["session"]["app_version"],
                    "device": r["session"]["device"], "final_level": r["result"]["final_level"],
                    "reason_count": len(r["result"]["reasons"])} for r in mine[:limit]]
        installs = len({r["session"]["install_id"] for r in rows
                        if net24 and r["session"]["net24"] == net24 and r["session"]["received_at"] >= since})
        return history, installs

    def save(self, session: dict, retrieved: dict, result: dict) -> str:
        key = (session["install_id"], session["session_id"])
        with self._lock:
            if key in self._keys:
                raise Duplicate()
            pk = str(uuid.uuid4())
            stored = dict(session, id=pk, received_at=datetime.now(timezone.utc))
            self._rows[pk] = {"session": stored, "retrieved": retrieved, "result": result}
            self._keys[key] = pk
        return pk

    def list_sessions(self, install_id, min_level, limit) -> list[dict]:
        with self._lock:
            rows = list(self._rows.values())
        rows = [r for r in rows if (not install_id or r["session"]["install_id"] == install_id)
                and (not min_level or r["result"]["final_level"] >= min_level)]
        rows.sort(key=lambda r: r["session"]["received_at"], reverse=True)
        return [{"id": r["session"]["id"], "install_id": r["session"]["install_id"],
                 "session_id": r["session"]["session_id"], "received_at": r["session"]["received_at"].isoformat(),
                 "action": r["session"]["action"], "final_level": r["result"]["final_level"],
                 "risk_score": r["result"].get("risk_score"),
                 "label": r["result"]["label"], "outcome": r["result"]["outcome"],
                 "rules_level": r["result"]["rules_level"], "ml_level": r["result"]["ml_level"],
                 "ml_status": r["result"]["ml_status"]} for r in rows[:limit]]

    def training_features(self, max_rules_level: int, limit: int) -> list[dict]:
        with self._lock:
            rows = [r for r in self._rows.values() if r["result"]["rules_level"] <= max_rules_level]
        return [{"features": r["result"]["features"], "rules_level": r["result"]["rules_level"]} for r in rows[:limit]]
