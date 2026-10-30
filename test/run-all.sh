#!/data/data/com.termux/files/usr/bin/bash
# test/run-all.sh
# One command, three suites, no network dependency except the loopback listener.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
rc=0
for t in test/local-harness.mjs test/bypass-logic-test.mjs; do
  echo "== $t"
  node "$t" || rc=1
  echo
done
echo "== test/portal-hit-vs-fake-portal.sh"
bash test/portal-hit-vs-fake-portal.sh || rc=1
exit $rc
