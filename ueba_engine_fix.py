#!/usr/bin/env python3
"""
Patch script for ueba_engine.py — fixes the file handle invalidation bug.

The bug:
  _patch_campaign_ids() calls os.replace(tmp_path, self.output_path)
  which atomically swaps the file. But the main run() loop holds an open
  file handle (out_file) to the OLD inode. After the swap, all subsequent
  writes go to the orphaned old inode — a ghost file with no directory entry.
  The data is written and flushed successfully but is permanently lost.

  Result: ueba_alerts.jsonl stops growing after the first campaign cluster
  run (typically ~5 minutes after startup). The engine log shows alerts
  but the file stays at the pre-swap line count forever.

The fix:
  1. Move out_file out of the with-block so it can be reopened.
  2. After _patch_campaign_ids does the swap, reopen the handle.
  3. Use a threading.Event to signal the main loop to reopen safely.

Usage:
  python3 ueba_engine_fix.py /root/NEW_DRIVE/aditya_ueba/ueba_engine.py
"""
import sys


# ── The two patches ──────────────────────────────────────────────────────────

PATCH_1_OLD = '''        with open(self.output_path, "a", encoding="utf-8") as out_file:
            with open(self.input_path, "r", encoding="utf-8",
                      errors="replace") as in_file:

                # Seek to last known position (resume support)
                # -1 sentinel = no state file = seek to END (live mode only)
                if self.state.position == -1:
                    in_file.seek(0, 2)  # seek to end of file
                    live_start = in_file.tell()
                    self.state.save(live_start)
                    log.info("No state file found — starting from END of input "
                             "(live mode). Position: %d", live_start)
                else:
                    in_file.seek(self.state.position)
                partial_line = ""

                while self.running:
                    chunk = in_file.read(65536)  # 64 KB at a time

                    if not chunk:
                        # No new data — sleep and poll
                        time.sleep(self.poll_ms / 1000.0)
                        continue

                    # Process chunk into complete lines
                    lines = (partial_line + chunk).split("\\n")
                    partial_line = lines[-1]  # may be incomplete

                    for line in lines[:-1]:
                        line = line.strip()
                        if not line:
                            continue

                        # Parse JSON
                        try:
                            log_entry = json.loads(line)
                        except json.JSONDecodeError:
                            self.stats["total_errors"] += 1
                            continue

                        # Process through UEBA pipeline
                        try:
                            result = self._process_log(log_entry)
                        except Exception as e:
                            log.debug("Processing error: %s", e)
                            self.stats["total_errors"] += 1
                            result = None

                        self.stats["total_processed"] += 1
                        events_since_save += 1

                        # Write anomalous log to output
                        if result is not None:
                            # Suppress noise events (high-volume low-value firewall
                            # policy events). They are still scored and added to
                            # FAISS/profiles — just not written to alerts output.
                            _meta = result.get("_metadata_cache", {})
                            _is_noise = _meta.get("is_noise", False)
                            # Fallback: check signature_id directly
                            if not _is_noise:
                                from ueba_preprocessor import is_noise as _is_noise_fn
                                _is_noise = _is_noise_fn(result)

                            if _is_noise:
                                self.stats.setdefault("total_suppressed", 0)
                                self.stats["total_suppressed"] += 1
                            else:
                                self.stats["total_alerts"] += 1
                                line_out = json.dumps(result, ensure_ascii=False)
                                out_file.write(line_out + "\\n")
                                out_file.flush()'''

PATCH_1_NEW = '''        # ── FIX: open output file as a plain handle (not with-block)
        # so we can reopen it after _patch_campaign_ids does its atomic swap.
        # Using a with-block meant the fd stayed bound to the old inode
        # after os.replace() — all writes silently went to a ghost file.
        import threading
        self._reopen_flag = threading.Event()
        out_file = open(self.output_path, "a", encoding="utf-8")
        try:
            with open(self.input_path, "r", encoding="utf-8",
                      errors="replace") as in_file:

                # Seek to last known position (resume support)
                # -1 sentinel = no state file = seek to END (live mode only)
                if self.state.position == -1:
                    in_file.seek(0, 2)  # seek to end of file
                    live_start = in_file.tell()
                    self.state.save(live_start)
                    log.info("No state file found — starting from END of input "
                             "(live mode). Position: %d", live_start)
                else:
                    in_file.seek(self.state.position)
                partial_line = ""

                while self.running:
                    # ── Reopen output file if campaign patcher swapped it ──
                    if self._reopen_flag.is_set():
                        try:
                            out_file.close()
                        except Exception:
                            pass
                        out_file = open(self.output_path, "a", encoding="utf-8")
                        self._reopen_flag.clear()
                        log.debug("Output file handle reopened after campaign swap")

                    chunk = in_file.read(65536)  # 64 KB at a time

                    if not chunk:
                        # No new data — sleep and poll
                        time.sleep(self.poll_ms / 1000.0)
                        continue

                    # Process chunk into complete lines
                    lines = (partial_line + chunk).split("\\n")
                    partial_line = lines[-1]  # may be incomplete

                    for line in lines[:-1]:
                        line = line.strip()
                        if not line:
                            continue

                        # Parse JSON
                        try:
                            log_entry = json.loads(line)
                        except json.JSONDecodeError:
                            self.stats["total_errors"] += 1
                            continue

                        # Process through UEBA pipeline
                        try:
                            result = self._process_log(log_entry)
                        except Exception as e:
                            log.debug("Processing error: %s", e)
                            self.stats["total_errors"] += 1
                            result = None

                        self.stats["total_processed"] += 1
                        events_since_save += 1

                        # Write anomalous log to output
                        if result is not None:
                            # Suppress noise events (high-volume low-value firewall
                            # policy events). They are still scored and added to
                            # FAISS/profiles — just not written to alerts output.
                            _meta = result.get("_metadata_cache", {})
                            _is_noise = _meta.get("is_noise", False)
                            # Fallback: check signature_id directly
                            if not _is_noise:
                                from ueba_preprocessor import is_noise as _is_noise_fn
                                _is_noise = _is_noise_fn(result)

                            if _is_noise:
                                self.stats.setdefault("total_suppressed", 0)
                                self.stats["total_suppressed"] += 1
                            else:
                                self.stats["total_alerts"] += 1
                                line_out = json.dumps(result, ensure_ascii=False)
                                out_file.write(line_out + "\\n")
                                out_file.flush()'''


PATCH_2_OLD = '''        # Final steps before exit
        self._log_stats()
        log.info("Stopping campaign detector and running final clustering...")
        self.campaign_detector.stop()   # triggers final _run_clustering() → callback
        self.profile_store.close()'''

PATCH_2_NEW = '''        except Exception:
            raise
        finally:
            # Always close the output file on exit, even if reopened mid-run
            try:
                out_file.close()
            except Exception:
                pass

        # Final steps before exit
        self._log_stats()
        log.info("Stopping campaign detector and running final clustering...")
        self.campaign_detector.stop()   # triggers final _run_clustering() → callback
        self.profile_store.close()'''


PATCH_3_OLD = '''            if changed > 0:
                os.replace(tmp_path, self.output_path)
                n_camps = len(set(v for v in campaign_map.values() if v))
                log.info("Campaign IDs patched: %d alerts → %d campaigns",
                         changed, n_camps)
            else:
                os.unlink(tmp_path)'''

PATCH_3_NEW = '''            if changed > 0:
                os.replace(tmp_path, self.output_path)
                n_camps = len(set(v for v in campaign_map.values() if v))
                log.info("Campaign IDs patched: %d alerts → %d campaigns",
                         changed, n_camps)
                # ── FIX: signal the main loop to reopen its output file handle.
                # os.replace() above atomically replaced self.output_path with
                # a new inode. The main loop's out_file fd now points to the
                # orphaned old inode — writes succeed but go to a ghost file.
                # Setting this flag tells the main loop to reopen on next iteration.
                if hasattr(self, "_reopen_flag"):
                    self._reopen_flag.set()
            else:
                os.unlink(tmp_path)'''


def apply(path):
    with open(path, encoding="utf-8") as f:
        content = f.read()

    original = content

    patches = [
        ("Patch 1 (reopen handle in run loop)", PATCH_1_OLD, PATCH_1_NEW),
        ("Patch 2 (finally block to close file)", PATCH_2_OLD, PATCH_2_NEW),
        ("Patch 3 (set reopen flag after swap)", PATCH_3_OLD, PATCH_3_NEW),
    ]

    for name, old, new in patches:
        if old not in content:
            print(f"✗ {name}: string not found — already applied or mismatch")
            sys.exit(1)
        content = content.replace(old, new, 1)
        print(f"✓ {name}")

    if content == original:
        print("No changes made.")
        sys.exit(1)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"\n✓ Patched: {path}")
    print("\nRestart the engine:")
    print("  pkill -f ueba_engine.py && sleep 2 && python3 ueba_engine.py &")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} ueba_engine.py")
        sys.exit(1)
    apply(sys.argv[1])
