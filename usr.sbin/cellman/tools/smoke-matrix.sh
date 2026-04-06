#!/bin/sh

set -eu

if [ $# -ge 1 ]; then
  CELLMAN_BIN=$1
  shift
else
  CELLMAN_BIN=cellman
fi

if [ $# -ge 1 ]; then
  DSL_DIR=$1
  shift
else
  DSL_DIR="$(dirname "$0")/../examples/samples"
fi

if [ ! -x "$CELLMAN_BIN" ] && ! command -v "$CELLMAN_BIN" >/dev/null 2>&1; then
  echo "missing cellman binary: $CELLMAN_BIN" >&2
  exit 1
fi

PASS=0
FAIL=0
SKIP=0

run_expect() {
  header=$1
  expected=$2
  shift 2

  if CELLMAN_DSL_DIR="$DSL_DIR" "$CELLMAN_BIN" "$@" >/dev/null 2>&1; then
    rc=0
  else
    rc=$?
  fi

  case ",${expected}," in
    *",${rc},"*)
      PASS=$((PASS + 1))
      echo "PASS  $header"
      ;;
    *)
      FAIL=$((FAIL + 1))
      echo "FAIL  $header (rc=${rc}, expected=${expected})"
      ;;
  esac
}

run_or_skip_runtime() {
  header=$1
  expected=$2
  shift 2

  if [ "$(id -u)" -ne 0 ] || ! command -v cellctl >/dev/null 2>&1; then
    SKIP=$((SKIP + 1))
    echo "SKIP  $header (needs root + cellctl)"
    return 0
  fi

  run_expect "$header" "$expected" "$@"
}

echo "Running read-contract smoke matrix"

run_expect "cell list merged" "0" cell list
run_expect "cell list desired tsv" "0" cell list --view desired -T
run_expect "cell list runtime tsv nohdr" "0" cell list --view runtime -T -H
run_expect "cell list projection" "0" cell list --view merged -o name,running,state -T

run_expect "cell show merged" "0" cell show example
run_expect "cell show desired projection" "0" cell show example --view desired -o name,state,autostart -T
run_expect "cell fields desired" "0" cell fields --view desired -T

run_expect "volume list merged" "0" volume list
run_expect "volume list runtime" "0" volume list --view runtime -T
run_expect "volume show projection" "0" volume show example --view merged -o name,manifest,runtime,mounted -T
run_expect "volume fields runtime" "0" volume fields --view runtime -T

echo "Running apply/lifecycle smoke matrix"

run_or_skip_runtime "apply dry-run all" "0,2" apply --all --dry-run
run_or_skip_runtime "apply dry-run target" "0,2" apply example --dry-run
run_or_skip_runtime "apply dry-run force" "0,2" apply example --dry-run --force
run_or_skip_runtime "apply restart-changed" "0" apply example --restart-changed --silent
run_or_skip_runtime "cell plan run named" "0" cell plan run example --file "$DSL_DIR/03-apply-example.lua" --ephemeral

echo
echo "Result: pass=${PASS} fail=${FAIL} skip=${SKIP}"
if [ "$FAIL" -ne 0 ]; then
  exit 1
fi
exit 0
