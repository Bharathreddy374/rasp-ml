"""Persistence. One interface, two implementations:

  PostgresStore  production. Every request is three round trips at most: find, lookup, save.
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
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Protocol
from urllib.parse import parse_qs, unquote, urlsplit

import pg8000.dbapi as pg

SCHEMA_SQL = Path(__file__).resolve().parent.parent / "db" / "schema.sql"
GRAPH_WINDOW = timedelta(days=7)
GRAPH_DEPTH = 2


class Duplicate(Exception):
    """The (install_id, session_id) pair is already stored."""


class StoreError(Exception):
    """The database could not be reached or the statement failed."""


@dataclass
class LookupQuery:
    """What the retrieval stage asks the database for one request."""
    install_id: str
    now: datetime
    net24: str | None = None
    asn: int | None = None
    sensor_sig: str | None = None
    android_id_hash: str | None = None
    history_limit: int = 200

    def graph_keys(self) -> list[str]:
        """The attributes that link installs in the device graph."""
        keys = [f"net:{self.net24}"] if self.net24 else []
        if self.android_id_hash:
            keys.append(f"aid:{self.android_id_hash}")
        return keys or ["none:"]


@dataclass
class Graph:
    """The connected component of this install (other installs only), over 7 days of links:
    same /24 network or same hashed Android ID, up to GRAPH_DEPTH hops."""
    members: int = 0
    emulator: int = 0          # members whose latest session had EM_EMULATOR
    new: int = 0               # members first seen in the last 24 h
    risky: int = 0             # members whose latest level is 4 or 5
    level_sum: int = 0


@dataclass
class LookupResult:
    history: list[dict] = field(default_factory=list)  # this install's sessions, newest first
    net_installs_24h: int = 0
    net_new_installs_24h: int = 0
    net_sessions_30d: int = 0
    net_risky_sessions_30d: int = 0
    asn_installs_24h: int = 0       # other installs
    sensor_installs_24h: int = 0    # other installs
    aid_other_installs_30d: int = 0
    graph: Graph = field(default_factory=Graph)


class Store(Protocol):
    def migrate(self) -> None: ...
    def ping(self) -> bool: ...
    def find(self, install_id: str, session_id: str) -> dict | None: ...
    def get(self, pk: str) -> dict | None: ...
    def lookup(self, q: LookupQuery) -> LookupResult: ...
    def save(self, session: dict, retrieved: dict, result: dict) -> str: ...
    def list_sessions(self, install_id: str | None, min_level: int | None, limit: int) -> list[dict]: ...
    def training_features(self, max_rules_level: int, limit: int) -> list[dict]: ...


# ---------------------------------------------------------------------------------------
# PostgreSQL
# ---------------------------------------------------------------------------------------
_LOOKUP_SQL = """
WITH RECURSIVE
edges AS (
    SELECT DISTINCT install_id, 'net:' || net24 AS k FROM collect_sessions
     WHERE net24 IS NOT NULL AND received_at >= %s
    UNION
    SELECT DISTINCT install_id, 'aid:' || android_id_hash FROM collect_sessions
     WHERE android_id_hash IS NOT NULL AND received_at >= %s
),
walk(k, depth) AS (
    SELECT k, 0 FROM unnest(%s::text[]) AS t(k)
    UNION
    SELECT e2.k, w.depth + 1 FROM walk w
      JOIN edges e1 ON e1.k = w.k
      JOIN edges e2 ON e2.install_id = e1.install_id
     WHERE w.depth < %s
),
members AS (
    SELECT DISTINCT e.install_id FROM edges e JOIN walk w ON w.k = e.k WHERE e.install_id <> %s
),
firsts AS (
    SELECT install_id, min(received_at) AS first_seen FROM collect_sessions GROUP BY install_id
),
latest AS (
    SELECT DISTINCT ON (s.install_id) s.install_id, r.final_level, COALESCE(r.reasons, '[]'::jsonb) AS reasons
      FROM collect_sessions s JOIN members m ON m.install_id = s.install_id
      LEFT JOIN session_results r ON r.session_id = s.id
     ORDER BY s.install_id, s.received_at DESC
),
stats AS (
    SELECT
      (SELECT count(DISTINCT install_id) FROM collect_sessions WHERE net24 = %s AND received_at >= %s) AS net_installs_24h,
      (SELECT count(DISTINCT c.install_id) FROM collect_sessions c JOIN firsts f ON f.install_id = c.install_id
        WHERE c.net24 = %s AND c.received_at >= %s AND f.first_seen >= %s) AS net_new_installs_24h,
      (SELECT count(*) FROM collect_sessions c JOIN session_results r ON r.session_id = c.id
        WHERE c.net24 = %s AND c.received_at >= %s) AS net_sessions_30d,
      (SELECT count(*) FROM collect_sessions c JOIN session_results r ON r.session_id = c.id
        WHERE c.net24 = %s AND c.received_at >= %s AND r.final_level >= 4) AS net_risky_sessions_30d,
      (SELECT count(DISTINCT install_id) FROM collect_sessions WHERE asn = %s AND install_id <> %s AND received_at >= %s) AS asn_installs_24h,
      (SELECT count(DISTINCT install_id) FROM collect_sessions WHERE sensor_sig = %s AND install_id <> %s AND received_at >= %s) AS sensor_installs_24h,
      (SELECT count(DISTINCT install_id) FROM collect_sessions
        WHERE android_id_hash = %s AND install_id <> %s AND received_at >= %s) AS aid_other_installs_30d,
      (SELECT count(*) FROM latest) AS g_members,
      (SELECT count(*) FROM latest WHERE reasons @> '[{"code": "EM_EMULATOR"}]') AS g_emulator,
      (SELECT count(*) FROM latest l JOIN firsts f ON f.install_id = l.install_id WHERE f.first_seen >= %s) AS g_new,
      (SELECT count(*) FROM latest WHERE final_level >= 4) AS g_risky,
      (SELECT COALESCE(sum(final_level), 0) FROM latest) AS g_level_sum
)
SELECT stats.*, h.* FROM stats LEFT JOIN (
    SELECT s.received_at, s.scan_time, s.client_ip, s.app_version, s.device, s.device_context AS context,
           s.signals -> 'F067' AS kernel, r.final_level,
           COALESCE(jsonb_array_length(r.reasons), 0) AS reason_count,
           (r.ml ->> 'anomaly_pct')::float AS anomaly_pct
      FROM collect_sessions s LEFT JOIN session_results r ON r.session_id = s.id
     WHERE s.install_id = %s ORDER BY s.received_at DESC LIMIT %s
) h ON TRUE
ORDER BY h.received_at DESC NULLS LAST
"""

_STAT_KEYS = ("net_installs_24h", "net_new_installs_24h", "net_sessions_30d", "net_risky_sessions_30d",
              "asn_installs_24h", "sensor_installs_24h", "aid_other_installs_30d")
_HISTORY_KEYS = ("received_at", "scan_time", "client_ip", "app_version", "device", "context", "kernel",
                 "final_level", "reason_count", "anomaly_pct")


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

    def lookup(self, q: LookupQuery) -> LookupResult:
        """Everything the retrieval stage needs from the database, in ONE statement."""
        d1, d7, d30 = q.now - timedelta(days=1), q.now - GRAPH_WINDOW, q.now - timedelta(days=30)
        args = (
            d7, d7,                                   # edges
            q.graph_keys(), GRAPH_DEPTH,              # walk
            q.install_id,                             # members
            q.net24, d1,                              # net_installs_24h
            q.net24, d1, d1,                          # net_new_installs_24h
            q.net24, d30,                             # net_sessions_30d
            q.net24, d30,                             # net_risky_sessions_30d
            q.asn, q.install_id, d1,                  # asn_installs_24h (other installs)
            q.sensor_sig, q.install_id, d1,           # sensor_installs_24h (other installs)
            q.android_id_hash, q.install_id, d30,     # aid_other_installs_30d
            d1,                                       # g_new
            q.install_id, q.history_limit,            # history
        )

        def work(cur):
            rows = _fetch(cur, _LOOKUP_SQL, args)
            first = rows[0]
            out = LookupResult(**{k: int(first[k] or 0) for k in _STAT_KEYS})
            out.graph = Graph(members=int(first["g_members"]), emulator=int(first["g_emulator"]),
                              new=int(first["g_new"]), risky=int(first["g_risky"]), level_sum=int(first["g_level_sum"]))
            out.history = [_plain({k: r[k] for k in _HISTORY_KEYS}) for r in rows if r["received_at"] is not None]
            return out
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
                   payload_bytes, app_version, device, app, signals, unknown, failed_groups,
                   device_context, asn, sensor_sig, android_id_hash, header_hash, ja3)
                VALUES (%s::uuid, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb,
                        %s::jsonb, %s, %s, %s, %s, %s)
            ), r AS (
                INSERT INTO session_retrievals (session_id, server_signals, not_computed, history, checks, retrieval_ms)
                VALUES (%s::uuid, %s::jsonb, %s::jsonb, %s::jsonb, %s::jsonb, %s)
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
             None if session.get("device_context") is None else _j(session["device_context"]),
             session.get("asn"), session.get("sensor_sig"),
             session.get("android_id_hash"), session.get("header_hash"), session.get("ja3"),
             pk, _j(retrieved["server_signals"]), _j(retrieved.get("not_computed") or {}), _j(retrieved["history"]), _j(retrieved["checks"]),
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

    def lookup(self, q: LookupQuery) -> LookupResult:
        with self._lock:
            rows = [r for r in self._rows.values()]
        s = lambda r: r["session"]  # noqa: E731
        d1, d7, d30 = q.now - timedelta(days=1), q.now - GRAPH_WINDOW, q.now - timedelta(days=30)
        first_seen: dict[str, datetime] = {}
        for r in rows:
            i = s(r)["install_id"]
            first_seen[i] = min(first_seen.get(i, s(r)["received_at"]), s(r)["received_at"])

        def installs(pred) -> set:
            return {s(r)["install_id"] for r in rows if pred(r)}

        out = LookupResult()
        if q.net24:
            out.net_installs_24h = len(installs(lambda r: s(r)["net24"] == q.net24 and s(r)["received_at"] >= d1))
            out.net_new_installs_24h = len({i for i in installs(lambda r: s(r)["net24"] == q.net24 and s(r)["received_at"] >= d1)
                                            if first_seen[i] >= d1})
            net30 = [r for r in rows if s(r)["net24"] == q.net24 and s(r)["received_at"] >= d30]
            out.net_sessions_30d = len(net30)
            out.net_risky_sessions_30d = sum(1 for r in net30 if r["result"]["final_level"] >= 4)
        if q.asn is not None:
            out.asn_installs_24h = len(installs(lambda r: s(r).get("asn") == q.asn and s(r)["install_id"] != q.install_id and s(r)["received_at"] >= d1))
        if q.sensor_sig:
            out.sensor_installs_24h = len(installs(lambda r: s(r).get("sensor_sig") == q.sensor_sig and s(r)["install_id"] != q.install_id and s(r)["received_at"] >= d1))
        if q.android_id_hash:
            out.aid_other_installs_30d = len(installs(lambda r: s(r).get("android_id_hash") == q.android_id_hash
                                                      and s(r)["install_id"] != q.install_id and s(r)["received_at"] >= d30))

        # device graph: breadth-first walk over shared keys, same rules as the SQL
        edges: dict[str, set] = {}
        keys_of: dict[str, set] = {}
        for r in rows:
            if s(r)["received_at"] < d7:
                continue
            for k in ([f"net:{s(r)['net24']}"] if s(r)["net24"] else []) + \
                     ([f"aid:{s(r)['android_id_hash']}"] if s(r).get("android_id_hash") else []):
                edges.setdefault(k, set()).add(s(r)["install_id"])
                keys_of.setdefault(s(r)["install_id"], set()).add(k)
        frontier, seen_keys = set(q.graph_keys()), set(q.graph_keys())
        for _ in range(GRAPH_DEPTH):
            nxt = {k2 for k in frontier for i in edges.get(k, ()) for k2 in keys_of.get(i, ())} - seen_keys
            seen_keys |= nxt
            frontier = nxt
        members = {i for k in seen_keys for i in edges.get(k, ())} - {q.install_id}
        latest = {}
        for r in rows:
            i = s(r)["install_id"]
            if i in members and (i not in latest or s(r)["received_at"] > s(latest[i])["received_at"]):
                latest[i] = r
        out.graph = Graph(
            members=len(latest),
            emulator=sum(1 for r in latest.values() if any(x["code"] == "EM_EMULATOR" for x in r["result"]["reasons"])),
            new=sum(1 for i in latest if first_seen[i] >= d1),
            risky=sum(1 for r in latest.values() if r["result"]["final_level"] >= 4),
            level_sum=sum(r["result"]["final_level"] for r in latest.values()))

        mine = sorted((r for r in rows if s(r)["install_id"] == q.install_id), key=lambda r: s(r)["received_at"], reverse=True)
        out.history = [{"received_at": s(r)["received_at"].isoformat(), "scan_time": s(r)["scan_time"].isoformat(),
                        "client_ip": s(r)["client_ip"], "app_version": s(r)["app_version"], "device": s(r)["device"],
                        "context": s(r).get("device_context"), "kernel": s(r)["signals"].get("F067"),
                        "final_level": r["result"]["final_level"], "reason_count": len(r["result"]["reasons"]),
                        "anomaly_pct": (r["result"].get("ml") or {}).get("anomaly_pct")}
                       for r in mine[:q.history_limit]]
        return out

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
