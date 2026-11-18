#!/usr/bin/env bash
# Restore the files captured before the 09-Nov-2026 deployment and restart.
#
# Restores exactly what was snapshotted: the five Python files, the weekly
# retrain script, and ueba_config.yaml. The config is included because the
# deployment appended a model_tiers block to it, and rolling the scorer back
# without the config would leave a block referring to a tier the restored
# scorer does not implement -- harmless, but confusing to the next reader.
#
# Usage:  bash /opt/ueba/rollback_deploy.sh [snapshot-dir]
set -euo pipefail
SNAP="${1:-$(cat /opt/ueba/.rollback-latest 2>/dev/null || true)}"
[ -n "$SNAP" ] && [ -d "$SNAP" ] || { echo "no snapshot: $SNAP"; exit 1; }
echo "restoring from $SNAP"
for f in ueba_entities.py ueba_engine.py ueba_preprocessor.py \
         ueba_dashboard_server.py ueba_weekly_retrain.sh ueba_config.yaml \
         ueba_models/autoencoder.py; do
  if [ -f "$SNAP/$f" ]; then
    cp -p "$SNAP/$f" "/opt/ueba/$f"
    echo "  restored $f"
  fi
done
echo "restarting services"
systemctl restart ueba-engine
systemctl restart ueba-dashboard
sleep 8
systemctl is-active ueba-engine ueba-dashboard
echo "rolled back."
