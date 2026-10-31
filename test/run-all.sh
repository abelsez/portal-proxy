#!/data/data/com.termux/files/usr/bin/bash
# test/run-all.sh — one command, every suite, no network needed (loopback only).
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
rc=0
for t in test/local-harness.mjs test/bypass-logic-test.mjs; do
  echo "== $t"; node "$t" || rc=1; echo
done
for t in test/portal-hit-vs-fake-portal.sh test/portal-find-test.sh; do
  echo "== $t"; bash "$t" || rc=1; echo
done
[ $rc -eq 0 ] && echo "ALL SUITES GREEN" || echo "SOMETHING FAILED"
exit $rc
