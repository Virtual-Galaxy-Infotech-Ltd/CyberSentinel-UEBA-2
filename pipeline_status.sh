#!/usr/bin/env bash
# pipeline_status.sh — is the L1..L4 correlation pipeline actually processing?
# Read-only. Run on the SIEM host.  bash pipeline_status.sh
#
# "Running" is not the same as "working": the layers can be up while Kafka
# offsets sit still. The delta check below is the one that settles it.

P=/home/vgipl/CyberSentinel-Event-Correlation-Kafka

echo "===== 1. ARE THE SIX LAYERS RUNNING? ====="
for s in normalizer.py enrich_json.py unified_correlation_engine.py \
         context_scorer.py kafka_jsonl_sink.py pipeline.py; do
  n=$(pgrep -fc "$s" 2>/dev/null || echo 0)
  printf "  %-34s %s\n" "$s" "$([ "$n" -gt 0 ] && echo "UP ($n proc)" || echo "DOWN")"
done

echo
echo "===== 2. ARE OFFSETS MOVING? (the real test) ====="
read_off() {
  for t in normalized enriched incidents scored; do
    v=$(docker exec siem-kafka kafka-get-offsets --bootstrap-server localhost:9092 \
          --topic "$t" --time -1 2>/dev/null \
        || docker exec siem-kafka kafka-run-class kafka.tools.GetOffsetShell \
          --bootstrap-server localhost:9092 --topic "$t" --time -1 2>/dev/null)
    s=$(echo "$v" | awk -F: '{s+=$3} END {print s+0}')
    echo "$t $s"
  done
}
A=$(read_off); sleep 30; B=$(read_off)
printf "  %-12s %>14s %14s %10s\n" topic before after delta 2>/dev/null || true
echo "  topic          before            after         delta"
while read -r t before; do
  after=$(echo "$B" | awk -v k="$t" '$1==k{print $2}')
  printf "  %-12s %14s %16s %9s\n" "$t" "$before" "$after" "$((after - before))"
done <<< "$A"
echo "  (all deltas 0 after 30s = NOT processing)"

echo
echo "===== 3. IS THE ENRICHED OUTPUT GROWING? ====="
ls -lt "$P/data/enriched" 2>/dev/null | head -3
echo "  files in last 10 min: $(find "$P/data/enriched" -type f -mmin -10 2>/dev/null | wc -l | tr -d ' ')"

echo
echo "===== 4. LAST WORDS IN THE PIPELINE LOG ====="
echo "  log mtime: $(stat -c %y "$P/pipeline.log" 2>/dev/null)"
tail -15 "$P/pipeline.log" 2>/dev/null

echo
echo "===== 5. DID IT CRASH AGAIN ON THE SAME THING? ====="
grep -c "MSG_SIZE_TOO_LARGE" "$P/pipeline.log" 2>/dev/null | sed 's/^/  MSG_SIZE_TOO_LARGE occurrences: /'
tail -2000 "$P/pipeline.log" 2>/dev/null | grep -niE "crashed|traceback|Force-killing|Shutting down" | tail -8
