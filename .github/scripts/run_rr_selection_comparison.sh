#!/usr/bin/env bash
# Build both revisions before interleaved measurement on one hosted runner.
set -euo pipefail

export RR_COMPARISON_ROOT="$PWD"
export RR_COMPARISON_OUTPUT="$PWD/tests/performance/ci_results/rr-comparison"
if [ -e "$RR_COMPARISON_OUTPUT" ]; then
  echo '::error::comparison output must be new; stale results cannot be reused'
  exit 1
fi
mkdir -p "$RR_COMPARISON_OUTPUT"
RR_CANDIDATE_SHA="$(git rev-parse HEAD)"
export RR_CANDIDATE_SHA
if [ -z "${RR_BASE_SHA:-}" ]; then
  if [ "${GITHUB_EVENT_NAME:-}" != workflow_dispatch ]; then
    echo '::error::this event must supply its baseline SHA'
    exit 1
  fi
  RR_BASE_SHA="$(git rev-parse HEAD^)"
fi
if ! [[ "$RR_BASE_SHA" =~ ^[0-9a-f]{40}$ ]] || [ "$RR_BASE_SHA" = 0000000000000000000000000000000000000000 ]; then
  echo '::error::baseline must be an immutable nonzero commit SHA'
  exit 1
fi
export RR_BASE_SHA
git cat-file -e "$RR_BASE_SHA^{commit}"
# A random source path changes Cargo identities for the root and patched path
# dependencies outside the standalone mesh workspace. Compile both revisions
# at the SAME deterministic path; keep binaries and prior source trees separate.
RR_COMPARISON_WORK="$RUNNER_TEMP/ferrum-rr-comparison"
export RR_COMPARISON_WORK
mkdir "$RR_COMPARISON_WORK"
RR_COMPARISON_SOURCE="$RR_COMPARISON_WORK/source"
export RR_COMPARISON_SOURCE
export CARGO_TARGET_DIR="$PWD/tests/performance/mesh/target"
python3 .github/scripts/run_rr_selection_comparison.py self-test
rustc -Vv > "$RR_COMPARISON_OUTPUT/rustc-version.txt"
cargo -Vv > "$RR_COMPARISON_OUTPUT/cargo-version.txt"
lscpu --json > "$RR_COMPARISON_OUTPUT/cpu.json"
for role in candidate baseline; do
  export RR_COMPARISON_ROLE="$role"
  revision="$RR_CANDIDATE_SHA"
  if [ "$role" = baseline ]; then
    revision="$RR_BASE_SHA"
  fi
  git -c core.hooksPath=/dev/null worktree add --detach "$RR_COMPARISON_SOURCE" "$revision"
  # The only source overlay is the candidate measurement harness.
  cp tests/performance/mesh/benches/rr_selection.rs "$RR_COMPARISON_SOURCE/tests/performance/mesh/benches/rr_selection.rs"
  /usr/bin/time --format='%e' --output="$RR_COMPARISON_OUTPUT/$role-compile.time" \
    cargo bench --manifest-path "$RR_COMPARISON_SOURCE/tests/performance/mesh/Cargo.toml" --bench rr_selection --no-run --locked --message-format=json \
    > "$RR_COMPARISON_OUTPUT/$role-compile.jsonl"
  python3 .github/scripts/run_rr_selection_comparison.py record-build
  # Preserve each freshly created tree, including any build-script outputs.
  # The next revision starts from a clean checkout at the identical source path.
  git -c core.hooksPath=/dev/null worktree move "$RR_COMPARISON_SOURCE" "$RR_COMPARISON_WORK/$role-source"
done

for round in 1 2 3; do
  export RR_COMPARISON_ROUND="$round"
  if [ "$round" = 2 ]; then
    order='candidate baseline'
  else
    order='baseline candidate'
  fi
  for role in $order; do
    export RR_COMPARISON_ROLE="$role"
    export FERRUM_RR_CRITERION_ROOT="$RR_COMPARISON_OUTPUT/$role-$round"
    if [ "$role" = baseline ]; then
      "$RR_COMPARISON_WORK/baseline" --bench --noplot rr_selection/2_targets > "$RR_COMPARISON_OUTPUT/$role-$round.log" 2>&1
    else
      "$RR_COMPARISON_WORK/candidate" --bench --noplot rr_selection/2_targets > "$RR_COMPARISON_OUTPUT/$role-$round.log" 2>&1
    fi
    python3 .github/scripts/run_rr_selection_comparison.py record-round
  done
done
python3 .github/scripts/verify_rr_selection_benchmark.py --criterion-root "$RR_COMPARISON_OUTPUT"
