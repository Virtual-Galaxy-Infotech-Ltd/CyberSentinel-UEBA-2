#!/bin/bash
# One-off retrain, scheduled by hand for a quiet hour.
#
# Differs from ueba_weekly_retrain.sh on purpose:
#   * no chunk pull and no bundling — the 2026-11-01 weekly snapshot is
#     already in training_zips/ and its corpus is already built;
#   * --skip-prepare — the 84 GB corpus and 10.16 GB features.h5 from 01 Nov
#     are intact and good. The weekly run died AFTER prepare succeeded, at the
#     trainer, because prepare and the trainer disagreed about where
#     features.h5 lived. Re-running prepare would delete 10 GB of valid work
#     and spend 30-90 minutes rebuilding it identically.
#
# The engine IS stopped: training needs the memory. This box sits at ~103 of
# 125 GB used with swap exhausted, so leaving the engine running risks the
# OOM killer picking off the engine or the Kafka forwarders.
set -uo pipefail

LOG=/opt/ueba/logs/retrain_oneoff.log
cd /opt/ueba || exit 1

say() { echo "$(date '+%F %T')  $*" >> "$LOG"; }

say "=============================================================="
say "one-off retrain starting (engine will be stopped)"
free -g >> "$LOG" 2>&1

say "stopping ueba-engine"
systemctl stop ueba-engine
sleep 5
say "engine state: $(systemctl is-active ueba-engine)"

say "running retrain.py --skip-prepare"
./venv/bin/python3 retrain.py --skip-prepare >> "$LOG" 2>&1
RC=$?
say "retrain.py exit code: $RC"

say "starting ueba-engine"
systemctl start ueba-engine
sleep 20
say "engine state: $(systemctl is-active ueba-engine)"

if [ "$RC" -eq 0 ]; then
  say "SUCCESS — new models promoted. Newest model file:"
  ls -lt models/autoencoders/ 2>/dev/null | sed -n 2p >> "$LOG"
  say "model count: $(ls -1 models/autoencoders/ 2>/dev/null | wc -l)"
else
  say "FAILED — live models were left untouched (retrain.py stages first)."
fi
say "finished"
