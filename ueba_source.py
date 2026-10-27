#!/usr/bin/env python3
"""
ueba_source.py
──────────────
CyberSentinel UEBA — where events come from.

The engine used to tail one append-only file, `enriched.jsonl`, with a byte
offset persisted in `.state/ueba.state`. That file was assembled by
ueba_sync_bridge.sh, which pulled rotated `.jsonl.gz` chunks over SSH from the
SOC machine and appended them locally.

Co-locating UEBA on the SIEM host removes the need for any of that, because the
SIEM's own correlation pipeline already publishes every enriched event to a
Kafka topic. `kafka_jsonl_sink.py` in that pipeline is merely *another consumer*
writing the topic down to files — so the files are derived data and we can read
the topic directly instead.

What that buys, measured against the file path:

  * durable offsets maintained by Kafka, replacing our own byte counter
  * replay after an outage, up to topic retention
  * no second copy of the data on disk (~30 GB/day at the observed 66 events/s)
  * backpressure handled by the consumer group rather than by custom logic
  * no SSH, which removes two bug classes the bridge hit historically: `ssh`
    inheriting a loop's stdin, and `zcat` over the wire shipping plaintext

Both sources are kept. The file source is still the right answer when UEBA runs
somewhere that cannot reach the broker, and keeping it means the Kafka path can
be switched off without a code change if it misbehaves in production.

CONSUMER GROUP — READ THIS BEFORE CHANGING IT
─────────────────────────────────────────────
The engine MUST use its own group (default `ueba-engine`). Kafka divides a
topic's partitions among the members of a group, so joining an existing one —
`enriched-file-sink`, `enricher`, `correlation`, `scorer` — would make UEBA
*steal* partitions from that consumer. The SIEM's file sink would silently stop
receiving a share of events and nobody would see an error. A separate group
gets its own offsets over the same messages, which is what we want.
"""

import json
import logging
import time
from pathlib import Path

log = logging.getLogger("ueba.source")

try:
    import orjson
    _loads = orjson.loads
except ImportError:
    _loads = json.loads


class SourceError(RuntimeError):
    """Raised when a source cannot be opened or is misconfigured."""


class _Source:
    """Interface the engine consumes.

    batches() is a generator yielding lists of parsed events. It blocks and
    polls internally, so the engine's loop stays a simple `for` over it and the
    polling cadence belongs to the source, not the engine.

    checkpoint() persists progress. It is deliberately explicit and called by
    the engine on its own cadence, not automatically per batch — the engine
    already knows how many events it has handled since the last save, and an
    offset committed before the alerts were written would lose alerts on a
    crash.
    """

    name = "source"

    def open(self):
        raise NotImplementedError

    def batches(self, batch_size, running):
        raise NotImplementedError

    def checkpoint(self):
        raise NotImplementedError

    def close(self):
        pass

    def describe(self):
        return self.name

    # Parse errors are counted, never raised: in a stream of millions a few
    # malformed lines are normal and must not stop the engine.
    def _parse(self, raw, stats):
        try:
            return _loads(raw)
        except Exception:
            stats["errors"] += 1
            return None


class FileTailSource(_Source):
    """Tail one append-only JSONL file, resuming from a saved byte offset.

    This reproduces the behaviour the engine had inline, including the two
    subtleties that matter:

      * a partial trailing line is carried to the next read rather than parsed,
        because a chunk boundary lands mid-line roughly every time
      * a position of -1 (no state file) means seek to END, not to 0. Starting
        a fresh deployment by replaying the whole retained file would flood the
        alert store with historical anomalies presented as current.
    """

    name = "file"

    def __init__(self, path, state, chunk_bytes=1048576, poll_ms=100):
        self.path = str(path)
        self.state = state
        self.chunk_bytes = int(chunk_bytes)
        self.poll_ms = int(poll_ms)
        self._fh = None
        self._partial = ""

    def open(self):
        # The engine previously waited here for the file to appear; keep that,
        # because on a fresh host the pipeline may not have written it yet.
        self._fh = open(self.path, "r", encoding="utf-8", errors="replace")
        if self.state.position == -1:
            self._fh.seek(0, 2)
            pos = self._fh.tell()
            self.state.save(pos)
            log.info("No state file — starting from END of %s (live mode) at %d",
                     self.path, pos)
        else:
            self._fh.seek(self.state.position)
            log.info("Resuming %s at byte %d", self.path, self.state.position)
        return self

    def batches(self, batch_size, running):
        stats = {"errors": 0}
        while running():
            chunk = self._fh.read(self.chunk_bytes)
            if not chunk:
                time.sleep(self.poll_ms / 1000.0)
                continue

            lines = (self._partial + chunk).split("\n")
            self._partial = lines[-1]

            parsed = []
            for line in lines[:-1]:
                line = line.strip()
                if not line:
                    continue
                rec = self._parse(line, stats)
                if rec is not None:
                    parsed.append(rec)

            for start in range(0, len(parsed), batch_size):
                yield parsed[start:start + batch_size], stats["errors"]
                stats["errors"] = 0

    def checkpoint(self):
        if self._fh is not None:
            self.state.save(self._fh.tell())

    def close(self):
        try:
            self.checkpoint()
        finally:
            if self._fh is not None:
                self._fh.close()
                self._fh = None

    def describe(self):
        return "file:%s" % self.path


class KafkaSource(_Source):
    """Consume enriched events from a Kafka topic.

    Offsets live in Kafka under our own consumer group, so `.state/ueba.state`
    is unused on this path. Auto-commit is OFF: the engine commits via
    checkpoint() only after the batch's alerts have been written, so a crash
    re-delivers the last batch rather than dropping it. Duplicate alerts are
    recoverable; missing ones are not.
    """

    name = "kafka"

    def __init__(self, brokers, topic, group="ueba-engine",
                 poll_ms=100, offset_reset="latest", extra=None):
        self.brokers = brokers
        self.topic = topic
        self.group = group
        self.poll_ms = int(poll_ms)
        self.offset_reset = offset_reset
        self.extra = dict(extra or {})
        self._consumer = None

    # Group names used by the SIEM's own pipeline. Joining one of these would
    # take partitions away from that consumer — see the module docstring.
    RESERVED_GROUPS = {
        "enricher", "correlation", "scorer",
        "enriched-file-sink", "scored-file-sink",
    }

    def open(self):
        if self.group in self.RESERVED_GROUPS:
            raise SourceError(
                "consumer group %r belongs to the SIEM pipeline; using it would "
                "steal partitions from that consumer. Pick a UEBA-specific "
                "group such as 'ueba-engine'." % self.group)
        try:
            from confluent_kafka import Consumer
        except ImportError as e:
            raise SourceError(
                "confluent-kafka is not installed, which the kafka source "
                "needs. Either `pip install confluent-kafka` or set "
                "streaming.source: file in ueba_config.yaml.") from e

        conf = {
            "bootstrap.servers": self.brokers,
            "group.id": self.group,
            "auto.offset.reset": self.offset_reset,
            "enable.auto.commit": False,
            # The engine is a single process; a long poll is cheap and keeps
            # the broker from treating a quiet period as a dead member.
            "session.timeout.ms": 45000,
            "max.poll.interval.ms": 600000,
        }
        conf.update(self.extra)
        self._consumer = Consumer(conf)
        self._consumer.subscribe([self.topic])
        log.info("Kafka source: %s topic=%s group=%s reset=%s",
                 self.brokers, self.topic, self.group, self.offset_reset)
        return self

    def batches(self, batch_size, running):
        from confluent_kafka import KafkaError

        stats = {"errors": 0}
        while running():
            msgs = self._consumer.consume(num_messages=batch_size,
                                          timeout=self.poll_ms / 1000.0)
            if not msgs:
                continue

            parsed = []
            for m in msgs:
                err = m.error()
                if err is not None:
                    # End of partition is normal and means "caught up".
                    if err.code() != KafkaError._PARTITION_EOF:
                        log.warning("kafka message error: %s", err)
                        stats["errors"] += 1
                    continue
                val = m.value()
                if not val:
                    continue
                rec = self._parse(val, stats)
                if rec is not None:
                    parsed.append(rec)

            if parsed or stats["errors"]:
                yield parsed, stats["errors"]
                stats["errors"] = 0

    def checkpoint(self):
        if self._consumer is not None:
            try:
                self._consumer.commit(asynchronous=False)
            except Exception as e:
                # A failed commit means at-least-once redelivery, not data
                # loss, so it must not take the engine down.
                log.warning("kafka commit failed (will redeliver): %s", e)

    def close(self):
        if self._consumer is not None:
            try:
                self.checkpoint()
            finally:
                try:
                    self._consumer.close()
                except Exception:
                    pass
                self._consumer = None

    def describe(self):
        return "kafka:%s/%s@%s" % (self.brokers, self.topic, self.group)


def build_source(config, state):
    """Pick the source from `streaming.source` in ueba_config.yaml.

    Defaults to 'file' so an existing deployment keeps its behaviour when this
    module lands without a config change.
    """
    streaming = config.get("streaming", {}) or {}
    kind = str(streaming.get("source", "file")).strip().lower()

    if kind == "file":
        return FileTailSource(
            path=config["paths"]["enriched_input"],
            state=state,
            chunk_bytes=streaming.get("read_chunk_bytes", 1048576),
            poll_ms=streaming.get("poll_interval_ms", 100),
        )

    if kind == "kafka":
        kcfg = streaming.get("kafka", {}) or {}
        brokers = kcfg.get("brokers")
        topic = kcfg.get("topic", "enriched")
        if not brokers:
            raise SourceError(
                "streaming.source is 'kafka' but streaming.kafka.brokers is "
                "unset. On the SIEM host the pipeline uses localhost:39092 — "
                "note 9092 is only the in-container listener.")
        return KafkaSource(
            brokers=brokers,
            topic=topic,
            group=kcfg.get("group", "ueba-engine"),
            poll_ms=streaming.get("poll_interval_ms", 100),
            offset_reset=kcfg.get("offset_reset", "latest"),
            extra=kcfg.get("client_config", {}) or {},
        )

    raise SourceError("unknown streaming.source %r (expected 'file' or 'kafka')"
                      % kind)


# ── selftest ──────────────────────────────────────────────────────────────────

def selftest():
    """Exercise the file source against real files. No Kafka needed.

        python3 ueba_source.py --selftest
    """
    import tempfile

    fails = []

    def ck(name, got, exp):
        ok = got == exp
        if not ok:
            fails.append(name)
        print("  %-54s %s" % (name, "ok" if ok else "FAIL got=%r exp=%r"
                              % (got, exp)))

    class FakeState:
        def __init__(self, pos=-1):
            self.position = pos
            self.saves = []

        def save(self, p):
            self.position = p
            self.saves.append(p)

    d = Path(tempfile.mkdtemp())
    f = d / "enriched.jsonl"

    def drain(src, batch_size=2, rounds=1):
        """Pull a bounded number of batches so the generator cannot block."""
        out, n = [], 0
        gen = src.batches(batch_size, lambda: n < rounds)
        for parsed, errs in gen:
            out.append((parsed, errs))
            n += 1
            if n >= rounds:
                break
        return out

    print("no state file => seek to END, backlog is NOT replayed")
    f.write_text('{"a":1}\n{"a":2}\n')
    st = FakeState(-1)
    s = FileTailSource(f, st, chunk_bytes=1024, poll_ms=1).open()
    ck("saved position is EOF", st.position, f.stat().st_size)
    ck("nothing yielded from the backlog", drain(s, 2, 0), [])
    s.close()

    print("\nnew lines after open are delivered")
    with open(f, "a") as fh:
        fh.write('{"a":3}\n{"a":4}\n')
    st2 = FakeState(f.stat().st_size - len('{"a":3}\n{"a":4}\n'))
    s2 = FileTailSource(f, st2, chunk_bytes=1024, poll_ms=1).open()
    b = drain(s2, 10, 1)
    ck("one batch", len(b), 1)
    ck("two events", [r["a"] for r in b[0][0]], [3, 4])
    s2.close()

    print("\nresume from a saved byte offset")
    st3 = FakeState(0)
    s3 = FileTailSource(f, st3, chunk_bytes=1024, poll_ms=1).open()
    b = drain(s3, 10, 1)
    ck("all four events replayed from 0", [r["a"] for r in b[0][0]], [1, 2, 3, 4])
    s3.close()
    ck("checkpoint saved EOF", st3.position, f.stat().st_size)

    print("\na line split across two reads is not lost or half-parsed")
    g = d / "split.jsonl"
    g.write_text('{"n":1}\n{"n":2}\n')
    st4 = FakeState(0)
    s4 = FileTailSource(g, st4, chunk_bytes=10, poll_ms=1).open()
    seen, n = [], 0
    gen = s4.batches(10, lambda: n < 6)
    for parsed, _ in gen:
        seen.extend(r["n"] for r in parsed)
        n += 1
        if len(seen) >= 2:
            break
    ck("both events recovered across chunk boundaries", sorted(seen)[:2], [1, 2])
    s4.close()

    print("\nmalformed lines are counted, not raised")
    h = d / "bad.jsonl"
    h.write_text('{"ok":1}\nNOT JSON\n{"ok":2}\n')
    st5 = FakeState(0)
    s5 = FileTailSource(h, st5, chunk_bytes=1024, poll_ms=1).open()
    b = drain(s5, 10, 1)
    ck("good events kept", [r["ok"] for r in b[0][0]], [1, 2])
    ck("bad line counted once", b[0][1], 1)
    s5.close()

    print("\nbatch_size is honoured")
    st6 = FakeState(0)
    s6 = FileTailSource(f, st6, chunk_bytes=1024, poll_ms=1).open()
    b = drain(s6, 2, 2)
    ck("first batch has 2", len(b[0][0]), 2)
    ck("second batch has 2", len(b[1][0]), 2)
    s6.close()

    print("\nbuild_source() dispatch and guards")
    cfg_file = {"paths": {"enriched_input": str(f)}, "streaming": {}}
    ck("defaults to file", build_source(cfg_file, FakeState(0)).name, "file")

    cfg_k = {"paths": {"enriched_input": str(f)},
             "streaming": {"source": "kafka",
                           "kafka": {"brokers": "localhost:39092"}}}
    ck("kafka selected", build_source(cfg_k, FakeState(0)).name, "kafka")
    ck("kafka default topic", build_source(cfg_k, FakeState(0)).topic, "enriched")
    ck("kafka default group", build_source(cfg_k, FakeState(0)).group, "ueba-engine")

    for bad, label in (
        ({"streaming": {"source": "kafka", "kafka": {}},
          "paths": {"enriched_input": str(f)}}, "missing brokers"),
        ({"streaming": {"source": "rabbit"},
          "paths": {"enriched_input": str(f)}}, "unknown source"),
    ):
        try:
            build_source(bad, FakeState(0))
            ck("rejects %s" % label, False, True)
        except SourceError:
            ck("rejects %s" % label, True, True)

    # The group guard is the one that protects the SIEM's own sink.
    try:
        KafkaSource("localhost:39092", "enriched",
                    group="enriched-file-sink").open()
        ck("refuses a SIEM pipeline group", False, True)
    except SourceError:
        ck("refuses a SIEM pipeline group", True, True)
    except Exception as e:
        ck("refuses a SIEM pipeline group (got %s)" % type(e).__name__, False, True)

    print("\n%s — %d failure(s)" % ("PASS" if not fails else "FAIL", len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        logging.basicConfig(level=logging.WARNING)
        sys.exit(selftest())
    print(__doc__)
