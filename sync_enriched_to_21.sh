#!/usr/bin/env bash
set -euo pipefail

SRC=/home/vgipl/CyberSentinel-Event-Correlation-Kafka/data/enriched
DAYS="${1:-15}"
LOG=/opt/ueba/logs/sync_enriched.log

ssh -o BatchMode=yes socdr1 'mkdir -p /data/ueba_enriched'

find "$SRC" -maxdepth 1 -name 'enriched_*.jsonl.gz' \
  -mtime -"$DAYS" -printf '%f\n' | sort > /tmp/enriched_list.txt

echo "Shipping $(wc -l < /tmp/enriched_list.txt) chunks from the last ${DAYS} days" | tee -a "$LOG"

rsync -av --partial --append-verify \
      --files-from=/tmp/enriched_list.txt \
      -e 'ssh -o BatchMode=yes' \
      "$SRC/" socdr1:/data/ueba_enriched/ 2>&1 | tee -a "$LOG"

echo "[$(date -Is)] sync complete" | tee -a "$LOG"
