#!/usr/bin/env bash
# The full pre-release gate, as one command.
#
# WHY THIS EXISTS AS A SCRIPT AND NOT A LIST IN THE RUNBOOK: every safety in this
# repo is strongest where a mistake would be caught anyway and weakest where one
# person is working alone at speed. CI passes the feature flags and sets the
# anti-masking switch, so CI cannot be fooled. A hand-composed local command can be,
# and silently -- a suite whose feature is missing prints "running 0 tests ... ok",
# and the end-to-end arms skip to a pass unless the switch is set.
#
# So the invocations below are not a convenience. Typing most of them, or dropping
# one --features argument, produces a green run that proves less than it appears to,
# in the exact loop where nobody is reviewing.
#
# THE SET MUST MATCH CI, AND SO MUST EACH INVOCATION. Every arm here corresponds to
# a step in .github/workflows/ci.yml; when a step is added there, add it here. A
# local gate covering a subset is worse than none, because it earns trust and then
# lets through exactly what it was trusted to catch.
#
# Matching the SET is not matching the STEPS: this gate once ran every CI arm and
# still diverged, because the e2e arm dropped CI's --test-threads=1. Copy the
# flags, not just the command.
#
# AND EVEN A PERFECT MATCH IS ONE PLATFORM. CI runs ubuntu AND windows; this runs
# wherever you are. A green gate followed by a red build is therefore EXPECTED for
# anything platform-dependent, and has already happened once: the endpoint manifest
# keyed rows by `str(Path)`, which is identical on posix and backslashed on Windows,
# so ubuntu passed while windows reported all 29 rows removed and re-added. Nothing
# runnable here could have caught it.
#
# So this gate's claim is bounded: it proves the checks pass ON THIS MACHINE. Treat
# path rendering, line endings, and shell builtins as unverified until CI says
# otherwise — and do not let a green run here become the reason to skip reading a
# red one there.
set -euo pipefail

cd "$(dirname "$0")/.."

# A FAILURE MUST SURVIVE `| tail -1`.
#
# Every arm already prints its own diagnostic, and I still lost a real failure to my
# own `| tail -1` three times in a row: the gate said GATE FAILED and the sentence
# explaining WHICH failure scrolled past above it. A summary line that omits the one
# fact you need is worse than no summary, because it looks like it told you.
#
# So the last thing printed carries the machine's state too. Contention is the common
# transient on a shared box and it reads exactly like a broken artifact; naming the
# load average at the moment of failure lets a reader tell them apart from the tail
# alone, without re-running and hoping it reproduces.
fail() {
  local load
  load="$(uptime 2>/dev/null | sed 's/.*load averages*: //' || echo unknown)"
  printf '\nGATE FAILED: %s  [load %s]\n' "$1" "$load" >&2
  printf '  Scroll up for the failing arm output. A high load average here means\n' >&2
  printf '  contention is a live suspect: the e2e arms time out under it.\n' >&2
  exit 1
}

# Run a command that produces no test counts, failing the gate if it does.
run_check() {
  local label="$1"; shift
  printf '\n=== %s ===\n' "$label"
  local out
  out="$("$@" 2>&1)" || { printf '%s\n' "$out"; fail "$label"; }
  printf '  ok\n'
}

# FORMAT AND LINT COME FIRST, because they are what CI fails on while a local run
# of the test arms alone passes.
#
# This gate was built to stop a hand-composed command proving less than it appears
# to -- and then omitted two of the checks CI runs, so "GATE PASSED" locally was
# followed by a red build on formatting. A gate that covers a subset of CI teaches
# people to trust it and then contradicts them, which is worse than no gate: it
# converts a fast local failure into a slow remote one.
#
# The clippy arms are run BOTH ways for the same reason the test arms are: code
# behind a feature flag is not compiled without it, so a lint error inside a
# crash-cut seam is invisible to the default invocation.
# The endpoint-host manifest is a population check, which no unit test can be: a
# per-constant assertion cannot fail when a NEW endpoint appears, and "is this URL
# asserted somewhere" is satisfied by a test comparing a constant to itself.
run_check "inbound contracts" bash scripts/check-inbound-contracts.sh
run_check "endpoint hosts" python3 scripts/endpoint-hosts.py
run_check "threshold controls" python3 scripts/threshold-controls.py
run_check "path rendering" python3 scripts/check-path-rendering.py
run_check "doc status" python3 scripts/check-doc-status.py
# FORMAT IS SCOPED TO THIS REPO'S OWN CRATES, and that is a correctness fix rather
# than a narrowing.
#
# `cargo fmt --all` reaches through the sibling PATH DEPENDENCIES (subc-core,
# cortexkit-store, ...) and checks their sources too. Those live in other repos,
# owned by other seats, and are edited while this gate runs -- so the arm's result
# depended on whether a peer happened to be MID-EDIT. Measured 2026-08-21: this gate
# failed on two diffs in subconscious's daemon_config.rs while that repo's COMMITTED
# tip formatted clean. Nothing in this repo was wrong and nothing in theirs was
# either; I was reading someone's unfinished work.
#
# THE WORSE DIRECTION IS THE QUIET ONE: it can also pass BECAUSE a sibling's
# uncommitted state happens to be clean, then fail in CI against their committed tip.
# A gate whose answer depends on another agent's working tree is not reproducible,
# and an irreproducible gate teaches people to re-run it rather than read it.
#
# The member list is DERIVED from cargo metadata rather than typed, because a
# hand-written -p list is an enumeration that drifts: add a crate, forget the list,
# and the arm silently stops checking it while still reporting ok. Refuses on an
# empty derivation for the same reason the test floor refuses an empty count.
FMT_PKGS=$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(" ".join("-p "+p["name"] for p in json.load(sys.stdin)["packages"]))')
[ -n "$FMT_PKGS" ] || fail "format (could not derive workspace members -- refusing to run an empty scope)"
# shellcheck disable=SC2086
run_check "format" cargo fmt $FMT_PKGS -- --check

run_check "clippy" \
  cargo clippy --locked --workspace --all-targets -- -D warnings
run_check "clippy (seam features)" \
  cargo clippy --locked --workspace --all-targets \
    --features kill9-test-seam,rotate-test-seam,login-test-seam,migration-tools -- -D warnings

# Run a cargo invocation and require at least `min` tests to have PASSED, and that
# no arm announced a skip.
#
# THE COUNT IS NECESSARY: `test result: ok` survives a suite that ran nothing, since
# a file gated behind an absent feature is not compiled and reports "running 0 tests".
#
# THE COUNT IS NOT SUFFICIENT: an arm that skips still reports itself as passed, so
# eight skipped e2e arms count as eight. Only the skip notice distinguishes them --
# and cargo CAPTURES test output unless --nocapture is passed, so callers that can
# skip must pass it or this check reads an empty stream and finds nothing. Measured:
# without --nocapture the notice is invisible here, with it all eight appear.
run_expect() {
  local min="$1" label="$2"; shift 2
  printf '\n=== %s ===\n' "$label"

  # THE SKIP CHECK BELOW DEPENDS ON A FLAG IT DOES NOT CONTROL, so enforce the
  # dependency here rather than describing it in a comment and hoping. `--nocapture`
  # is what makes a skip notice visible to this function; without it the guard reads
  # an empty stream, finds no notice, and reports the arm clean -- identical to a run
  # where nothing skipped. Nothing about the green says which happened. That flag is
  # exactly what a later tidy-up deletes: it is noisy, it looks like debug residue,
  # and removing it breaks no test. It silently disarms the guard instead.
  #
  # WHICH ARMS NEED IT IS DERIVED FROM SOURCE, NOT ASSUMED. The first version of this
  # check keyed on `--ignored` and was WRONG -- it fired on the release-artifact arm,
  # which is `#[ignore]` because it builds a release binary, not because it can skip.
  # `--ignored` conflates "can skip at runtime" with "expensive, run explicitly", and
  # only the first needs the flag. A guard keyed on the wrong property fails the build
  # for arms that were never at risk, which is how a correct-sounding guard gets
  # deleted wholesale instead of fixed.
  #
  # The source probe enforces one repository convention: a test-file skip notice uses
  # the literal `SKIPPING` token. It does not discover arbitrary skip paths, and it does
  # not inspect test-name filters; an arm is required to pass --nocapture when its target
  # file follows that convention. The output check below enforces the same token.
  local a want_target=0 target="" has_nocapture=0 before_separator=1
  for a in "$@"; do
    [ "$a" = "--nocapture" ] && has_nocapture=1
    if [ "$before_separator" = "1" ]; then
      if [ "$a" = "--" ]; then
        before_separator=0
        want_target=0
      elif [ "$want_target" = "1" ]; then
        target="$a"
        want_target=0
      elif [ "$a" = "--test" ]; then
        want_target=1
      fi
    fi
  done
  if [ -n "$target" ] && [ "$has_nocapture" = "0" ]; then
    local src
    src="$(find crates -path "*/tests/${target}.rs" -print -quit 2>/dev/null || true)"
    if [ -n "$src" ] && grep -q 'SKIPPING' "$src"; then
      fail "$label targets ${target}, whose source can print a skip notice, but omits \
--nocapture. cargo captures that notice, so the skip check below would read an empty \
stream and pass the arm without ever seeing it skip."
    fi
  fi

  local out
  out="$("$@" 2>&1)" || { printf '%s\n' "$out"; fail "$label"; }
  printf '%s\n' "$out" | grep -E '^test result:' || true
  if printf '%s\n' "$out" | grep -q 'SKIPPING'; then
    printf '%s\n' "$out" | grep 'SKIPPING' >&2
    fail "$label skipped an arm — it reported ok without running"
  fi
  # COULD-NOT-COUNT IS NOT ZERO, and conflating them made this gate lie for two weeks.
  #
  # This summed through `bc`, with `2>/dev/null || echo 0` behind it. On a host without
  # `bc` -- an undeclared dependency, and the only tool in this pipeline that is not
  # POSIX-guaranteed -- the pipeline failed, its reason was discarded, and the fallback
  # substituted a value that MEANS SOMETHING SPECIFIC AND FALSE. The gate then failed
  # closed (correct) while announcing "ran 0 tests, expected at least 402" (false),
  # about a suite in which all 402 had just passed.
  #
  # It stayed invisible from 2026-08-11 until an external contributor hit it on Arch,
  # because the count check only runs after the test command exits 0 -- so every green
  # run on a host WITH `bc` walked straight past it, and every host without one saw a
  # sentence about the test suite instead of about the missing tool.
  #
  # A FALLBACK VALUE THAT IS A VALID READING OF THE MEASUREMENT YOU FAILED TO MAKE IS
  # WORSE THAN AN ERROR. "0" is a legitimate test count, so it sends a reader hunting a
  # vanished suite. `awk` removes the undeclared dependency; the shape check below
  # names a counting failure as itself rather than dressing it as a measurement.
  #
  # The `|| passed=""` is load-bearing under `set -euo pipefail`, and dropping it looks
  # like tidying. Without it a failed summation aborts the whole script at the shell's
  # exit 127 BEFORE the check below can speak -- honest, since the shell names the
  # missing tool, but the operator gets a bare "command not found" with no indication
  # that the GATE decided nothing. Measured both ways.
  local passed
  passed="$(printf '%s\n' "$out" | grep -oE '^test result: ok\. [0-9]+ passed' \
    | grep -oE '[0-9]+' | awk '{ s += $1 } END { print s + 0 }')" || passed=""
  if ! printf '%s' "$passed" | grep -qE '^[0-9]+$'; then
    fail "$label: COULD NOT COUNT the tests (summation produced '$passed') -- this is a
  broken instrument, not a result. Do not read it as a test count; the arm's own
  'test result:' lines are printed above."
  fi
  if [ "$passed" -lt "$min" ]; then
    fail "$label ran $passed tests, expected at least $min — a suite that shrank is indistinguishable from one that passed"
  fi
}

# The floor is the MEASURED total, not a round number below it. A floor with slack
# is a check that tolerates exactly the defect it exists to catch: tests vanish one
# at a time (a misplaced #[test] attribute silently unregisters the function that
# follows it), and any gap between the floor and the real count is how many can go
# before anyone is told. Measured 402 across the workspace's suites at the time of
# writing; an earlier floor of 200 left a third of them free to disappear.
# The current measured total is 491 after adding the set-identity decrypt-arm and
# end-to-end usable-output regression pins.
#
# Raise this when tests are added. A failure here is normally that, not a defect --
# but it should be a deliberate edit rather than a number nobody revisits.
  run_expect 491 "workspace unit + integration" \
  cargo test --locked --workspace

# Two independent defences, because each catches what the other misses:
#   - CRED_REQUIRE_DAEMON=1 turns an unreachable sibling ck-subc into a failure at
#     source, before any arm can skip.
#   - --nocapture surfaces the skip notice so run_expect's check can see it, in case
#     an arm ever skips for a reason the switch does not cover.
# The count covers neither: skipped arms still report as passed.
#
# --test-threads=1 MATCHES CI. Each arm spawns a real ck-subc supervising a real
# module, and CI has always serialized them; this arm had silently dropped that.
#
# NOT A DIAGNOSIS OF THE FAILURE THAT PROMPTED IT. On 2026-08-11 this suite failed
# 8/8 with "daemon did not publish a connection file within 15s" during a gate run,
# then passed 8/8 alone minutes later. Parallelism was the first hypothesis and it
# is REFUTED -- a serialized run failed the same way, and afterwards the same
# serialized run passed. Machine load and output capture were tested and refuted
# too (an arm passes in 2.3s against a saturated box, and 8/8 pass piped with
# --nocapture). The cause is unexplained and the failure is not currently
# reproducible, so this flag is here for CI parity, NOT as a fix.
#
# If it recurs: the barrier is a 15s wait for the supervisor's connection file, so
# what needs capturing is the SUPERVISOR's own stderr at that moment -- the arm
# reports only that the file never appeared, which is an absence and says nothing
# about why. Do not let this comment become a claim that the flag settled it.
# THE FLOOR MUST MATCH THE POPULATION, and this one had drifted under it. It read 8
# against 9 live arms, so the ninth could vanish -- deleted, renamed out of the
# harness, gated behind an absent feature -- and the gate would still pass, because
# 8 of 9 clears a floor of 8. A floor below its population silently stops being a
# floor for the difference.
#
# Raise this WITH the arm count. A floor that trails is worse than no floor: it
# reports a bound it is not enforcing, and the gap is invisible from a green run.
CRED_REQUIRE_DAEMON=1 run_expect 9 "real-daemon e2e (ship gate)" \
  cargo test --locked -p credentials-module --test real_daemon_e2e -- \
    --ignored --nocapture --test-threads=1

# The crash-safety proofs are gated at FILE level: without the feature the file is
# not compiled and the run reports "running 0 tests ... ok". Nothing inside a file
# that does not exist can warn, so the counts are the only available instrument.
run_expect 1 "kill-9 mid-refresh crash cut" \
  cargo test --locked -p credentials-core --features kill9-test-seam --test kill9_mid_refresh
run_expect 5 "master-key rotation crash cuts" \
  cargo test --locked -p credentials-core --features rotate-test-seam --test rotate_crash_cut
run_expect 2 "login crash cut" \
  cargo test --locked -p credentials-core --features login-test-seam --test login_crash_cut
# The migration tools are feature-gated, so clippy compiles them but nothing RAN them
# until this arm existed. Compiling proves they build; the property that matters -- the
# key-identity diagnostic works while the daemon holds the lease -- is a runtime fact.
run_expect 1 "migration tools" \
  cargo test --locked -p credentials-core --features migration-tools \
  --test key_verify_takes_nothing

# The release-artifact assertion CI runs as its own step: the debug-only
# validation bypass must be absent from a --release binary. Ignored by default
# because it builds one.
run_expect 1 "release artifact (bypass absent)" \
  cargo test --locked -p credentials-module --test cli_admin \
  validation_bypass_is_absent -- --ignored --nocapture

# PROVE the scope claim rather than asserting it. "Every check CI runs" rots the
# moment CI grows an arm, and that is exactly how it broke: CI gained an inbound
# contract check and a release-artifact assertion, this gate did not, and its
# header still promised parity. A claim about another file has to be checked
# against that file or it is a comment pretending to be a guarantee.
# COUNT THE `test` JOB ONLY. The workflow gained a second job (`fork-safe`) whose
# steps re-run checks this gate ALREADY has, because a fork PR cannot mint the token
# for the private sibling checkouts and so cannot run the real suite at all. Counting
# every `- name:` in the file would read those duplicates as new CI coverage and
# demand arms that already exist -- and the fix for that pressure is to widen the
# bound, which is how this check stops checking. Bound the count to the job the claim
# is about instead.
ci_steps=$(awk '/^  test:/{j=1} /^  [a-z-]+:$/ && !/^  test:/{j=0} j && /^      - name:/{n++} END{print n+0}' \
    .github/workflows/ci.yml)
gate_arms=$(grep -cE '^run_(check|expect)' "$0")
# A zero here means the awk stopped matching the job or step shape, not that CI has no
# steps -- and it would sail under any gap bound. Refuse it: this is the same defect
# as the test-count check that reported "ran 0 tests" when it could not count them.
if [ "$ci_steps" -lt 5 ]; then
    printf '\nREFUSING: counted %s steps in the ci.yml `test` job.\n' "$ci_steps" >&2
    printf 'That is too few to be real, so the scan is broken rather than CI being\n' >&2
    printf 'empty -- and a broken scan here passes the gap check below silently.\n' >&2
    exit 1
fi
# CI has 4 setup steps (checkout x3, token mint) plus a build step that the gate
# gets for free by running in the workspace. Anything beyond that gap is a check
# CI runs and this gate does not.
if [ "$((ci_steps - gate_arms))" -gt 5 ]; then
    printf '\nREFUSING: CI has %s steps, this gate has %s arms.\n' "$ci_steps" "$gate_arms" >&2
    printf 'CI has grown past the gate; a subset-of-CI gate converts a fast local\n' >&2
    printf 'failure into a slow remote one. Add the missing arm, or widen this bound\n' >&2
    printf 'deliberately if the new step genuinely cannot run locally.\n' >&2
    exit 1
fi

# NAME THE LANE, not just the verdict. Two checkers whose success lines are
# indistinguishable let a transcript from one be read as covering the other --
# and the scope note in this header is read by whoever opens the file, never by
# whoever is looking at the output. Every arm here maps to a CI step, and the
# claim below is only true while that stays so: CI grew two steps past this gate
# (inbound contracts, release artifact) before anyone noticed, which is exactly
# the subset-of-CI failure this file's header says it exists to prevent.
printf '\nGATE PASSED -- every check CI runs, on this working tree\n'
printf '  NOT covered: cross-platform (CI also runs Windows), and whether a\n'
printf '  deployed BINARY carries what you just built (scripts/accept-deploy.sh).\n'
