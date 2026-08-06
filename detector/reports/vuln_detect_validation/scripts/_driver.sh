#!/usr/bin/env bash
# Run detect_vulns.py against vulnerable/ and patch/ of the 4 verify_samples
# that produced the report in ../README.md.
#
# Each scan writes its report to ../reports/<GO-ID>_<vuln|patch>.json
# and appends a stage-by-stage log line to ../logs/run.log.
#
# Usage (from reports/vuln_detect_validation/scripts/):
#   bash _driver.sh

set -u
cd "C:/Users/16655/Desktop/go"

ROOT="reports/vuln_detect_validation"
mkdir -p "$ROOT/reports" "$ROOT/logs"
LOG="$ROOT/logs/run.log"
: > "$LOG"

SAMPLES=(
  "ArchiveAndCompressionProcessing/GO-2020-0034"
  "QueryTemplateAndExpressionConstruction/GO-2023-1494"
  "NetworkRequestAndProtocolHandling/GO-2020-0024"
  "InputParsingAndDeserialization/GO-2022-0957"
)

for s in "${SAMPLES[@]}"; do
  id=$(basename "$s")
  for v in vulnerable patch; do
    target="verify_samples/$s/$v"
    out="$ROOT/reports/${id}_${v}.json"
    echo "" | tee -a "$LOG"
    echo "=== [$id/$v] target=$target ===" | tee -a "$LOG"
    t0=$(date +%s)
    python detect_vulns.py --target "$target" --output "$out" --no-copy --max-functions 5 --workers 1 2>&1 | tee -a "$LOG" | tail -25
    t1=$(date +%s)
    echo "[$id/$v] elapsed=$((t1-t0))s out=$out" | tee -a "$LOG"
  done
done

echo "" | tee -a "$LOG"
echo "=== ALL DONE ===" | tee -a "$LOG"
ls -la "$ROOT/reports/" | tee -a "$LOG"
