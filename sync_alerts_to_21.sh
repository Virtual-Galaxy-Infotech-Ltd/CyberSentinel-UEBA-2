#!/usr/bin/env bash
set -euo pipefail

SRC=/opt/ueba/archive/
DST=socdr1:/data/ueba_alerts/
LOG=/opt/ueba/logs/sync_alerts.log

mkdir -p /opt/ueba/logs
ssh -o BatchMode=yes socdr1 'mkdir -p /data/ueba_alerts'

rsync -av --partial --append-verify \
      --include='ueba_alerts_*.jsonl.zip' \
      --exclude='*' \
      -e 'ssh -o BatchMode=yes' \
      "$SRC" "$DST" 2>&1 | tee -a "$LOG"

echo "[$(date -Is)] sync complete" >> "$LOG"
