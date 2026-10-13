# UEBA rebuild runbook — standing up on a new server

Written for the Utho rebuild after box98 was decommissioned (October 2026), but
it is the general procedure for any fresh install.

Work top to bottom. Each step says how to know it worked before moving on.

---

## 0. Before you start — what you need

| | |
|---|---|
| **New server** | IP, root SSH, Ubuntu 22.04/24.04, Python 3.12 |
| **SIEM side** | host/IP (`10.200.10.23`), SSH user, path to `enriched_*.jsonl.gz` |
| **State bundle** | `ueba-state-restore-YYYYMMDD.tar.gz` (13 MB — see §2) |
| **Repo** | `git@github.com:Virtual-Galaxy-Infotech-Ltd/CyberSentinel-UEBA-2.git` |

**Sizing** — see the System Requirements table in `README.md`. Headline: RAM is
driven by the weekly retrain, not by detection. Detection needs ~24 GB; the
retrain previously peaked at 82 GB of `/dev/shm`. Disk ≈ 4.5 GB per million
events retained, plus ~120 GB working headroom.

---

## 1. What survived box98, and what did not

**Restored from the bundle** — these are irreplaceable or expensive to rebuild:

| | Why it matters |
|---|---|
| `fp_patterns.json` — **204 analyst-taught patterns** | months of analyst judgement; nothing regenerates it |
| `false_positives.json` | the FP records behind those patterns |
| `models/` — 453 autoencoders + IF + scaler + thresholds | lets day 1 detect instead of being blind |
| `profiles/user_profiles.db` | behavioural baselines |
| `agents.json` | endpoint registry |

**Gone, and the plan for each:**

| Lost | Plan |
|---|---|
| 190 GB training corpus | re-accumulate, or seed from SIEM history (§7) |
| `features.h5`, `vector_db` (FAISS) | regenerate at first retrain |
| `archive/` alert history | accepted loss |
| auth DB | recreate accounts (§6) |

**Know this going in:** the restored models are dated **2026-08-16** and cover
**453** entities; box98 had 543 after its 27 Sep retrain. So ~90 entities fall
back to the global model until the first retrain. Detection works from day 1 but
is not at full fidelity — plan the first retrain as soon as corpus allows.

---

## 2. Build the state bundle (on the machine that has it)

```bash
cd /Users/adityaumathe/CyberSentinel-Claude/ueba
tar czf ueba-state-restore-$(date +%Y%m%d).tar.gz \
    models/ profiles/user_profiles.db \
    fp_patterns.json false_positives.json fp_suppress_stats.json agents.json
```

**This bundle contains real usernames** (autoencoder filenames). It is gitignored
deliberately. Never push it; move it over SCP only.

> ⚠️ Until it is on the new server, this state exists on exactly one laptop.
> Copying it across is the first thing to do once SSH works.

---

## 3. Provision the server

```bash
ssh root@<utho-ip>
apt update && apt install -y python3.12 python3.12-venv git ssh rsync curl tar gzip cron
# preflight checks the rest
```

Pick the install directory now and use it consistently — the installer writes it
into every unit, path and cron entry. Default: `/opt/cybersentinel/ueba`.
**Put it on the big disk**, not the root volume.

✅ **Check:** `python3.12 --version`, and `df -h <install-dir>` shows the space you expect.

---

## 4. Clone and run the installer

```bash
git clone git@github.com:Virtual-Galaxy-Infotech-Ltd/CyberSentinel-UEBA-2.git /tmp/ueba-src
cd /tmp/ueba-src
./install_ueba.sh --dry-run     # read what it WILL do, first
./install_ueba.sh
```

It runs eight stages: preflight → site details → install location → SSH trust →
discovery → configuration → runtime → bring-up. It will ask for the SIEM host,
the enriched-logs path, and the dashboard bind address.

It handles the lab-specific values itself: every `/root/NEW_DRIVE/aditya_ueba`
becomes your install dir, and box98's IP is replaced with this host's in the
noise-suppression list.

✅ **Check:** `$BASE/ueba_site.env` exists and `UEBA_BASE` points at your install dir.

---

## 5. Reverse tunnel from the SIEM side

The bridge pulls from the SOC machine over SSH. Installer stage 4 generates a
keypair and helps authorise it.

```bash
# on the new server
ssh -i /root/.ssh/id_ueba <soc-user>@10.200.10.23 'ls /path/to/enriched | tail -3'
```

✅ **Check:** that command lists `enriched_*.jsonl.gz` without a password prompt.

If the SOC side reaches UEBA rather than the reverse, `deploy/systemd/sshd-tunnel.service`
is the autossh unit — point it at the new host.

---

## 6. Restore state (before starting the engine)

```bash
scp ueba-state-restore-*.tar.gz root@<utho-ip>:/tmp/
ssh root@<utho-ip>
cd $BASE && tar xzf /tmp/ueba-state-restore-*.tar.gz
chown -R root:root models profiles *.json
```

✅ **Check:**
```bash
ls models/autoencoders/*.pt | wc -l        # expect 453
ls models/autoencoders/global.pt           # MUST exist — bring-up gates on it
python3 -c "import json;print(len(json.load(open('fp_patterns.json'))))"   # 204
```

Then create the first admin — there are no default credentials by design:

```bash
./venv/bin/python3 ueba_auth.py create-admin --username <you>
./venv/bin/python3 ueba_auth.py check      # must say OK before enabling enforce
```

---

## 7. Seed the corpus (optional but valuable)

Without history the first retrain waits 21 days. If `10.200.10.23` still holds
archived enriched logs, pull them into the training corpus now and the first
retrain can happen in days instead of weeks.

```bash
./ueba_bootstrap_training.sh            # reports readiness, trains nothing
./ueba_bootstrap_training.sh --train    # build a baseline when ready
```

---

## 8. Bring up and verify

```bash
systemctl enable --now ueba-bridge ueba-dashboard
systemctl enable --now ueba-engine
systemctl enable --now ueba-engine-watchdog.timer
```

Verify **in this order** — each depends on the one before:

| # | Check | Expect |
|---|---|---|
| 1 | `ls -la $BASE/enriched.jsonl` | exists and **growing** |
| 2 | `grep "Stats \|" $BASE/logs/ueba_engine.stdout.log \| tail -2` | `processed` increasing |
| 3 | same line | `errors: 0` |
| 4 | `curl -s localhost:3026/api/health` | 200 |
| 5 | browser → `http://<ip>:3026` | tiles populate, feed has rows |
| 6 | `systemctl list-timers \| grep watchdog` | next run within 2 min |
| 7 | `crontab -l \| grep cybersentinel` | rotate 00:05, retrain Sun 03:30 |

**If `processed` stays at 0** but `enriched.jsonl` is growing: the engine is
running but scoring nothing — check `.state/ueba.state` position and that
`models/` restored correctly.

---

## 9. First-week watchlist

| When | Do |
|---|---|
| +1 h | alert rate sane? (box98 ran **0.04–0.09%**; wildly different means thresholds or models are off) |
| +24 h | rotation ran at 00:05 — `logs/rotate.log` |
| +24 h | `df -h` — corpus growth on track |
| +3 d | per-entity baselines meaningful; alert quality should improve |
| +7 d | first retrain if corpus seeded; otherwise schedule it |
| when stable | consider `auth.enforce: true` — **only after `ueba_auth.py check` says OK** |

---

## 10. Things that will bite you

1. **`global.pt` missing** → bring-up refuses to start the engine. Check §6.
2. **Install dir on the root volume** → fills, and that caused a 19-hour outage.
3. **`auth.enforce: true` with no admin** → everyone locked out. `check` first.
4. **Building the dashboard** must be done on the server (`npm run build`), not a laptop — toolchain versions differ.
5. **`ueba_rotate.sh` / watchdog on a stale path** — both now read `UEBA_BASE` from `ueba_site.env`; if you move the install, re-run the installer rather than editing paths.
6. **Models older than the feed's schema** — if the SIEM changed its event shape since August, feature extraction degrades silently. Watch `errors:` and the alert rate.

---

## 11. Rollback

Nothing here is destructive to the SIEM. If the rebuild goes wrong:

```bash
systemctl stop ueba-engine ueba-bridge ueba-dashboard ueba-engine-watchdog.timer
```

The SOC side is untouched — UEBA only ever reads from it. Re-run the installer
once the problem is understood; it is idempotent and replaces only its own
marked crontab block.
