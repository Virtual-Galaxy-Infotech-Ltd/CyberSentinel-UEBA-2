#!/usr/bin/env python3
"""
ueba_identity.py
────────────────
CyberSentinel UEBA — identity resolution: binding people to the machines and
addresses they were observed using, over time.

WHY THIS EXISTS
───────────────
Phase A merged the spellings of one account. Phase B split the flat entity
namespace into person/endpoint/service/shared/external. Neither of them can
answer the question an analyst actually asks:

    "endpoint:10.200.11.157 exfiltrated 4 GB at 02:30. WHO was that?"

Userless internal traffic — firewall, netflow, system events with no account
field — is the majority of what we ingest, and it resolves to a machine, not a
person. Attributing it needs a mapping from address/host to person, valid for a
bounded period of time, built from the events where both halves DO appear
together.

This is what the industry calls entity stitching. Splunk UBA builds it from
four sources (auth: IP→host, IP→user, host→user; DNS: IP→hostname; DHCP:
IP→MAC, IP→hostname; VPN: IP→user) and states that you need at least one of
them. Microsoft Sentinel takes the opposite approach and syncs an authoritative
IdentityInfo table out of Entra ID / AD rather than inferring it from logs.

WHAT WE CAN ACTUALLY BUILD TODAY — measured, not assumed
────────────────────────────────────────────────────────
Of Splunk's four sources we have exactly one. The event_category distribution
over a 3,412-alert production sample is auth 2,596 / system 523 / process 283 /
web 9 / other 1. There is no DHCP, DNS or VPN feed reaching UEBA at all.

So this is an auth-only stitcher, which is the documented minimum and nothing
more. Two consequences are designed for rather than papered over:

  * NO MAC COLUMN. A MAC address appears nowhere in the data — not under any of
    mac / src_mac / dst_mac / hwaddr / mac_address, at any nesting depth. A
    column for it would be permanently NULL and would imply a capability we do
    not have. The schema uses (kind, value) instead, so mac becomes a new kind
    the day a DHCP feed arrives, with no migration.

  * CONFIDENCE IS COMPUTED, NOT STORED. A per-source constant (auth=0.9,
    dhcp=0.8 ...) would be a number we invented. What actually determines
    whether an attribution is trustworthy is in the data: how many DISTINCT
    people were observed on that host or address, and how recently. In the
    sample, host 'Access-SRV-2.140' binds to three different people — any
    attribution from it is a guess — whereas 'Nidhi' binds to one. So
    confidence is derived at query time from exclusivity and recency. See
    owner_of().

SCOPE
─────
This module records and queries bindings. It does NOT yet feed scoring: using
a binding to re-attribute an endpoint's anomaly to a person changes detection
behaviour and therefore belongs with the retrain cutover, behind its own flag.
Populating the table is safe and additive in the meantime — the longer it runs
before that cutover, the better the history it has to answer from.
"""

import logging
import os
import sqlite3
from datetime import datetime, timedelta, timezone

log = logging.getLogger("ueba.identity")

# Where a timestamp is found on an event, in order of preference.
# `event_time` is present on 100% of the production sample; the others are
# fallbacks for differently-shaped input.
TIME_FIELDS = ("event_time", "ingest_time", "context.raw_event.timestamp",
               "timestamp", "@timestamp")

KIND_HOST = "host"
KIND_IP = "ip"
KINDS = (KIND_HOST, KIND_IP)

SOURCES = ("auth", "dhcp", "dns", "vpn", "manual")


def _parse_time(value):
    """ISO 8601 → aware datetime, or None. Never raises."""
    if not value:
        return None
    s = str(value).strip()
    if not s:
        return None
    # '+0530' → '+05:30'; fromisoformat is strict about the colon before 3.11.
    if len(s) >= 5 and s[-5] in "+-" and s[-3] != ":":
        s = s[:-2] + ":" + s[-2:]
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def event_time(log_entry, get_nested):
    """Best available timestamp for one event. `get_nested` is injected so this
    module does not import the preprocessor (which pulls in numpy and h5py)."""
    for field in TIME_FIELDS:
        dt = _parse_time(get_nested(log_entry, field))
        if dt:
            return dt
    return None


class IdentityBindings:
    """person ↔ (host | ip) observations, with the window each was seen in.

    Lives in the profile database alongside the `users` table, because the two
    are written from the same place on the same events and a second file would
    only add a way for them to disagree.
    """

    def __init__(self, db_path: str = None, retention_days: float = 90.0,
                 conn: sqlite3.Connection = None):
        """Pass `conn` to share a caller's connection, or `db_path` to open one.

        SHARE THE CONNECTION when the caller already has one on this database.
        Opening a second connection to the same SQLite file deadlocks it: this
        table is written mid-transaction from UserProfileStore.update(), so the
        binding connection holds a write lock that the profile store's own
        connection then waits on, and the next INSERT INTO users fails with
        "database is locked" — taking out profiling, which is far more
        important than a binding. One connection means one transaction and
        both tables commit together, which is also what makes the two tables
        consistent with each other by construction.
        """
        if conn is not None:
            self.conn = conn
            self._owns_conn = False
        elif db_path:
            os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self._owns_conn = True
        else:
            raise ValueError("IdentityBindings needs a db_path or a conn")
        self.retention_days = max(1.0, float(retention_days or 90.0))
        self._init_schema()

    def _init_schema(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS identity_bindings (
                person        TEXT    NOT NULL,
                kind          TEXT    NOT NULL,   -- 'host' | 'ip'
                value         TEXT    NOT NULL,   -- hostname or address
                source        TEXT    NOT NULL,   -- auth | dhcp | dns | vpn | manual
                observations  INTEGER NOT NULL DEFAULT 0,
                first_seen    TEXT    NOT NULL,
                last_seen     TEXT    NOT NULL,
                PRIMARY KEY (person, kind, value, source)
            )
        """)
        # The hot query is "who was on this value recently", so the index leads
        # with the lookup key and carries last_seen for the window filter.
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_bindings_lookup
            ON identity_bindings (kind, value, last_seen)
        """)
        self.conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_bindings_person
            ON identity_bindings (person)
        """)
        self.conn.commit()

    # ── write path ──────────────────────────────────────────────────────────
    def record(self, person: str, kind: str, value: str, when=None,
               source: str = "auth") -> bool:
        """Note that `person` was observed on `value`. Idempotent per window:
        a repeat observation bumps the counter and extends last_seen rather
        than inserting a row. Returns False for input it will not store."""
        if not person or not value or kind not in KINDS:
            return False
        if not str(person).startswith("person:"):
            # Only people get bound. A shared or service account is not one
            # actor, and an external address is not ours to attribute.
            return False
        if source not in SOURCES:
            source = "auth"

        when = when or datetime.now(timezone.utc)
        ts = when.isoformat()
        value = str(value).strip()

        cur = self.conn.execute(
            """UPDATE identity_bindings
                  SET observations = observations + 1,
                      first_seen   = MIN(first_seen, ?),
                      last_seen    = MAX(last_seen, ?)
                WHERE person = ? AND kind = ? AND value = ? AND source = ?""",
            (ts, ts, person, kind, value, source))
        if cur.rowcount == 0:
            self.conn.execute(
                """INSERT INTO identity_bindings
                       (person, kind, value, source, observations,
                        first_seen, last_seen)
                   VALUES (?, ?, ?, ?, 1, ?, ?)""",
                (person, kind, value, source, ts, ts))
        return True

    def record_event(self, entity_key: str, log_entry: dict, get_nested) -> int:
        """Extract every binding one event supports. Returns how many it wrote.

        Called with the entity key resolve_entity() already produced, so the
        two can never disagree about who this event belongs to.
        """
        if not str(entity_key).startswith("person:"):
            return 0

        when = event_time(log_entry, get_nested)
        host = (get_nested(log_entry, "host.name")
                or get_nested(log_entry, "agent.name")
                or get_nested(log_entry, "context.raw_event.agent.name"))
        src_ip = (get_nested(log_entry, "subject.ip")
                  or get_nested(log_entry, "data.srcip")
                  or get_nested(log_entry, "context.raw_event.data.srcip"))

        written = 0
        if host:
            written += self.record(entity_key, KIND_HOST, host, when)
        if src_ip:
            # Only private addresses. A person reached from a public address is
            # classified external: by Phase B and never arrives here, but
            # asserting it locally keeps this module correct on its own.
            try:
                import ipaddress
                if ipaddress.ip_address(str(src_ip).strip()).is_private:
                    written += self.record(entity_key, KIND_IP, src_ip, when)
            except ValueError:
                pass
        return written

    def commit(self):
        self.conn.commit()

    # ── read path ───────────────────────────────────────────────────────────
    def owner_of(self, kind: str, value: str, at=None,
                 window_days: float = None):
        """Who was on this host/address, best candidate first.

        Returns a list of dicts with person, observations, share and
        confidence. Empty when nothing is known — callers must handle that,
        because for most addresses nothing will be.

        CONFIDENCE is derived, for the reason given in the module docstring:

            confidence = share × recency

        `share` is this person's fraction of all observations on the value, so
        a host that three people use cannot yield a confident attribution to
        any one of them. `recency` decays linearly from 1.0 at the moment of
        last_seen to 0.0 at the edge of the window, so a binding from two
        months ago does not get to name a suspect today.

        The product is deliberately pessimistic. An attribution is meant to be
        a lead for an analyst, not a verdict, and a number that is honest about
        a shared server is more useful than one that is confidently wrong.
        """
        if kind not in KINDS or not value:
            return []
        at = at or datetime.now(timezone.utc)
        window = timedelta(days=float(window_days or self.retention_days))
        floor = (at - window).isoformat()

        rows = self.conn.execute(
            """SELECT person, SUM(observations), MIN(first_seen), MAX(last_seen)
                 FROM identity_bindings
                WHERE kind = ? AND value = ? AND last_seen >= ?
             GROUP BY person""",
            (kind, str(value).strip(), floor)).fetchall()
        if not rows:
            return []

        total = sum(r[1] or 0 for r in rows) or 1
        out = []
        for person, obs, first_seen, last_seen in rows:
            share = (obs or 0) / total
            seen = _parse_time(last_seen)
            if seen is None:
                recency = 0.0
            else:
                age = (at - seen).total_seconds()
                span = window.total_seconds() or 1.0
                recency = max(0.0, min(1.0, 1.0 - (age / span)))
            out.append({
                "person": person,
                "observations": obs or 0,
                "share": round(share, 4),
                "recency": round(recency, 4),
                "confidence": round(share * recency, 4),
                "first_seen": first_seen,
                "last_seen": last_seen,
            })
        out.sort(key=lambda d: (-d["confidence"], -d["observations"]))
        return out

    def bindings_for(self, person: str):
        """Everything known about one person, most-observed first."""
        return [
            {"kind": k, "value": v, "source": s, "observations": o,
             "first_seen": f, "last_seen": l}
            for k, v, s, o, f, l in self.conn.execute(
                """SELECT kind, value, source, observations, first_seen, last_seen
                     FROM identity_bindings WHERE person = ?
                 ORDER BY observations DESC""", (person,))
        ]

    def stats(self):
        row = self.conn.execute(
            """SELECT COUNT(*), COUNT(DISTINCT person),
                      COUNT(DISTINCT value), COALESCE(SUM(observations), 0)
                 FROM identity_bindings""").fetchone()
        shared = self.conn.execute(
            """SELECT COUNT(*) FROM (
                   SELECT value FROM identity_bindings
                    GROUP BY kind, value HAVING COUNT(DISTINCT person) > 1)"""
        ).fetchone()[0]
        return {"rows": row[0], "people": row[1], "values": row[2],
                "observations": row[3], "ambiguous_values": shared}

    def prune(self, at=None) -> int:
        """Drop bindings whose last_seen fell outside retention. Returns rows
        deleted. A binding is evidence about a period, so an expired one is
        not merely stale — keeping it would let a former laptop owner be named
        for what the current one did."""
        at = at or datetime.now(timezone.utc)
        floor = (at - timedelta(days=self.retention_days)).isoformat()
        cur = self.conn.execute(
            "DELETE FROM identity_bindings WHERE last_seen < ?", (floor,))
        self.conn.commit()
        return cur.rowcount

    def close(self):
        """Commit, and close only a connection this instance opened — closing a
        borrowed one would pull the floor out from under the caller."""
        try:
            self.conn.commit()
        finally:
            if self._owns_conn:
                self.conn.close()


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest():
    """Assert the binding contract. Uses a throwaway database; touches nothing.

        python3 ueba_identity.py --selftest
    """
    import tempfile

    fails = []

    def ck(name, got, exp):
        ok = got == exp
        if not ok:
            fails.append((name, got, exp))
        print("  %-56s %s" % (name, "ok" if ok else "FAIL got=%r exp=%r"
                              % (got, exp)))

    print("_parse_time (the production data uses '+0530', with no colon)")
    ck("'+0530' offset parses", _parse_time("2026-08-27T00:08:25.859+0530")
       .utcoffset(), timedelta(hours=5, minutes=30))
    ck("'+05:30' offset parses", _parse_time("2026-08-27T00:08:25.859000+05:30")
       .utcoffset(), timedelta(hours=5, minutes=30))
    ck("naive is treated as UTC", _parse_time("2026-08-27T00:08:25").tzinfo,
       timezone.utc)
    ck("Z suffix", _parse_time("2026-08-27T00:08:25Z").tzinfo is not None, True)
    ck("garbage is None, never a raise", _parse_time("not a time"), None)
    ck("empty is None", _parse_time(""), None)

    db = os.path.join(tempfile.mkdtemp(), "selftest.db")
    b = IdentityBindings(db, retention_days=90)
    T = datetime(2026, 10, 20, 12, 0, tzinfo=timezone.utc)

    print("\nrecord() only binds people")
    ck("rejects shared:", b.record("shared:root@x", "host", "h1", T), False)
    ck("rejects endpoint:", b.record("endpoint:10.0.0.1", "host", "h1", T), False)
    ck("rejects external:", b.record("external:8.8.8.8", "host", "h1", T), False)
    ck("rejects unknown kind", b.record("person:a", "mac", "aa:bb", T), False)
    ck("rejects empty value", b.record("person:a", "host", "", T), False)
    ck("accepts person:", b.record("person:nidhi", "host", "Nidhi", T), True)

    print("\nrepeat observations upsert, they do not duplicate")
    b.record("person:nidhi", "host", "Nidhi", T + timedelta(hours=1))
    b.record("person:nidhi", "host", "Nidhi", T + timedelta(hours=2))
    b.commit()
    row = b.bindings_for("person:nidhi")[0]
    ck("one row for three observations", b.stats()["rows"], 1)
    ck("observations counted", row["observations"], 3)
    ck("last_seen extended", row["last_seen"],
       (T + timedelta(hours=2)).isoformat())
    ck("first_seen held", row["first_seen"], T.isoformat())

    print("\nowner_of — a host only one person uses")
    o = b.owner_of("host", "Nidhi", at=T + timedelta(hours=2))
    ck("one candidate", len(o), 1)
    ck("share is 1.0", o[0]["share"], 1.0)
    ck("confident at last_seen", o[0]["confidence"] > 0.99, True)

    print("\nowner_of — a shared server (Access-SRV-2.140 really has 11 users)")
    for person, n in (("person:jinu", 6), ("person:firdous", 3),
                      ("person:aryan", 1)):
        for _ in range(n):
            b.record(person, "host", "Access-SRV-2.140", T)
    b.commit()
    o = b.owner_of("host", "Access-SRV-2.140", at=T)
    ck("all candidates returned", len(o), 3)
    ck("most-observed ranks first", o[0]["person"], "person:jinu")
    ck("share splits 6/10", o[0]["share"], 0.6)
    ck("NOT confident — this is the point", o[0]["confidence"] < 0.65, True)
    ck("shares sum to 1", round(sum(x["share"] for x in o), 4), 1.0)
    ck("counted as ambiguous", b.stats()["ambiguous_values"], 1)

    print("\nrecency — a stale binding must not name a suspect today")
    now = b.owner_of("host", "Nidhi", at=T + timedelta(hours=2))[0]["confidence"]
    d45 = b.owner_of("host", "Nidhi", at=T + timedelta(days=45))[0]["confidence"]
    ck("halfway through the window is ~half", 0.4 < d45 < 0.6, True)
    ck("decays", d45 < now, True)
    ck("past the window, nothing",
       b.owner_of("host", "Nidhi", at=T + timedelta(days=120)), [])

    print("\nunknowns and retention")
    ck("unknown value is empty, not a guess", b.owner_of("host", "nope"), [])
    ck("unknown kind is empty", b.owner_of("mac", "aa:bb"), [])
    rows = b.stats()["rows"]
    ck("prune drops expired", b.prune(at=T + timedelta(days=200)), rows)
    ck("empty afterwards", b.stats()["rows"], 0)
    b.close()

    print("\n%s — %d failure(s)"
          % ("PASS" if not fails else "FAIL", len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        sys.exit(selftest())
    print(__doc__)
