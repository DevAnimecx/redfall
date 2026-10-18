#!/usr/bin/env bash
# Week 1 gate: for every manifest vuln, apply the known-good patch and prove that
#   (a) the target's own test suite still passes, and
#   (b) the original PoC no longer succeeds.
# Then restore the baseline. Prints one line per vuln and a final summary.
#
# Set REDFALL_VERIFY_IDS to a space-separated subset to run a batch.
set -uo pipefail
cd "$(dirname "$0")/.."

export DB_HOST="${DB_HOST:-127.0.0.1}"
export DB_PORT="${DB_PORT:-5432}"
export DB_NAME="${DB_NAME:-vulnbank}"
export DB_USER="${DB_USER:-vulnbank}"
export DATABASE_URL="${DATABASE_URL:-postgresql://vulnbank:Sup3rS3cretBankPwd!@127.0.0.1:5432/vulnbank}"
export UPLOAD_DIR="$PWD/uploads"
# The secret-management patches (VULN-027, VULN-028) move credentials out of source
# and require them in the environment, so a patched build refuses to boot without
# these. Supplying them is the intended production configuration.
export JWT_SECRET="${JWT_SECRET:-range-only-jwt-secret-value}"
export DB_PASSWORD="${DB_PASSWORD:-Sup3rS3cretBankPwd!}"
export STRIPE_WEBHOOK_SECRET="${STRIPE_WEBHOOK_SECRET:-whsec_range_only_value}"

ALL_IDS=$(python3 -c "import yaml;print(' '.join(v['id'] for v in yaml.safe_load(open('manifest.yaml'))['vulns']))")
IDS="${REDFALL_VERIFY_IDS:-$ALL_IDS}"

# `patch` toggling is not a reliable way back to a known state: it auto-detects a
# reversed patch and re-applies it, which corrupts files after a few cycles. The
# baseline is therefore a real file copy.
PRISTINE=$(mktemp -d)
cp -r golden_baseline/src golden_baseline/tests "$PRISTINE"/

restore() {
  rm -rf src tests
  cp -r "$PRISTINE"/src "$PRISTINE"/tests .
  find src tests -name '*.rej' -o -name '*.orig' | xargs -r rm -f
}

is_neutralizable() {
  python3 -c "
import sys, yaml
v = next(x for x in yaml.safe_load(open('manifest.yaml'))['vulns'] if x['id'] == '$1')
sys.exit(0 if v['poc'].get('poc_neutralizable', True) else 1)
"
}

pass_count=0
fail_count=0
FAILURES=()

for id in $IDS; do
  restore

  if ! npx ts-node scripts/apply_patch.ts "$id" >/tmp/vb_apply.log 2>&1; then
    echo "APPLY-FAILED   $id  $(tail -1 /tmp/vb_apply.log)"
    FAILURES+=("$id apply"); fail_count=$((fail_count+1)); continue
  fi
  if grep -q "Reversed (or previously applied)" /tmp/vb_apply.log; then
    echo "DIRTY-TREE     $id  (patch was already applied)"
    FAILURES+=("$id dirty-tree"); fail_count=$((fail_count+1)); continue
  fi

  if ! npm run build >/tmp/vb_build.log 2>&1; then
    echo "BUILD-FAILED   $id"; tail -8 /tmp/vb_build.log
    FAILURES+=("$id build"); fail_count=$((fail_count+1)); continue
  fi

  ./scripts/run_local.sh stop >/dev/null 2>&1
  if ! ./scripts/run_local.sh start >/tmp/vb_boot.log 2>&1; then
    echo "BOOT-FAILED    $id"; tail -8 /tmp/vb_boot.log
    FAILURES+=("$id boot"); fail_count=$((fail_count+1)); continue
  fi

  if npx jest --runInBand --forceExit >/tmp/vb_test.log 2>&1; then
    tests="PASS"
  else
    tests="FAIL"
  fi

  if is_neutralizable "$id"; then
    if npx ts-node scripts/replay_poc.ts "$id" >/tmp/vb_poc.log 2>&1; then
      poc="STILL-EXPLOITABLE"
    else
      poc="NEUTRALIZED"
    fi
  else
    poc="N/A"
  fi

  if [[ "$tests" == "PASS" && ( "$poc" == "NEUTRALIZED" || "$poc" == "N/A" ) ]]; then
    verdict="OK"
    pass_count=$((pass_count+1))
  else
    verdict="GATE-FAIL"
    FAILURES+=("$id tests=$tests poc=$poc"); fail_count=$((fail_count+1))
  fi

  printf '%-10s %-9s tests=%-4s poc=%s\n' "$id" "$verdict" "$tests" "$poc"
done

restore
./scripts/run_local.sh stop >/dev/null 2>&1
rm -rf "$PRISTINE"

echo
echo "verified: $pass_count / $((pass_count+fail_count))"
if [[ ${#FAILURES[@]} -gt 0 ]]; then
  echo "failures:"
  printf '  - %s\n' "${FAILURES[@]}"
  exit 1
fi
exit 0
