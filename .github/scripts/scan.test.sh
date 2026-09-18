#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/work/.github/scripts"
failures=0
# Deliberately not the shipped digest: the argv is only evidence that the body passes on what it
# was given, and a body hardcoding the real one would match a pin that named it too.
SCANNER_PIN="example.invalid/scanner@sha256:0000000000000000000000000000000000000000000000000000000000000000"

fail() {
    echo "  $1"
    failures=$((failures + 1))
}

# Real shapes: anything conditioned on the structure of a lockfile or of a SARIF result is a no-op
# on a token, and passes a test written with one.
cat >"$tmp/lockfile" <<'EOF'
[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "fe0f37c9e8f3c5a4a66ad655a93c74daac4ad00c441533bf5c6e7990bb42604e"
EOF
cat >"$tmp/sarif" <<'EOF'
{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"osv-scanner","rules":[{"id":"RUSTSEC-2021-0003"}]}},
"results":[{"ruleId":"RUSTSEC-2021-0003","level":"warning","message":{"text":"smallvec@1.6.0 is affected"},
"locations":[{"physicalLocation":{"artifactLocation":{"uri":"Cargo.lock"}}}]}]}]}
EOF

stub() {
    cat >"$tmp/bin/docker" <<EOF
#!/usr/bin/env bash
{ printf 'CALL\n'; printf '%s\n' "\$@"; } >>"$tmp/argv"
lock=""
outdir=""
for arg in "\$@"; do
    case "\$arg" in
        *:/scan/Cargo.lock | *:/scan/Cargo.lock:ro) lock=\${arg%%:*} ;;
        *:/out) outdir=\${arg%%:*} ;;
    esac
done
cat "\$lock" >"$tmp/lockfile-seen" 2>/dev/null || printf 'MISSING' >"$tmp/lockfile-seen"
if [ -n "\$outdir" ]; then
    case ${2:-results} in
        results) cp "$tmp/sarif" "\$outdir/results.sarif" ;;
        link) ln -s "$tmp/private" "\$outdir/results.sarif" ;;
        nothing) : ;;
    esac
    printf 'x' >"\$outdir/decoy"
    mkdir -p "\$outdir/.git" && printf 'x' >"\$outdir/.git/config"
fi
exit $1
EOF
    chmod +x "$tmp/bin/docker"
}

run_gate() {
    stub "$1" "${2:-results}"
    : >"$tmp/argv"
    cp "$tmp/lockfile" "$tmp/work/Cargo.lock"
    printf '[package]\n' >"$tmp/work/Cargo.toml"
    rm -rf "$tmp/elsewhere" "$tmp/work/decoy" "$tmp/work/.git"
    ln -sf "${3:-$tmp/elsewhere}" "$tmp/work/results.sarif"
    cp "$here/scan.sh" "$tmp/work/.github/scripts/scan.sh"
    (cd "$tmp/work" && PATH="$tmp/bin:$PATH" \
        env SCANNER="$SCANNER_PIN" GITHUB_WORKSPACE="$tmp/work" \
        bash .github/scripts/scan.sh) >"$tmp/out" 2>&1
}

out_mount() { sed -n 's#^\(/.*\):/out$#\1#p' "$tmp/argv"; }

# Either way the image would hold a writable path in the tree the job checked out, which is the
# whole of what mounting one file instead avoids.
outside_the_workspace() {
    local real work
    real=$(readlink -m "$1")
    work=$(readlink -m "$tmp/work")
    case "$real" in "$work" | "$work"/*) return 1 ;; esac
    case "$work" in "$real"/*) return 1 ;; esac
}

# A child that kept the workspace in a file of its own, or only in its own memory, is out of reach
# of all four probes below, so this catches a leftover, not a deliberate one.
outlived_the_gate() {
    local pids real
    # A /proc link reads canonically, so a TMPDIR reached through a symlink never matches $tmp.
    real=$(readlink -m "$tmp")
    mapfile -t pids < <({
        set +e  # a /proc entry belonging to someone else is a non-zero grep, not a reason to stop
        grep -laF "$tmp" /proc/[0-9]*/environ /proc/[0-9]*/cmdline
        find /proc -maxdepth 2 -name cwd \( -lname "$tmp*" -o -lname "$real*" \)
        find /proc -maxdepth 3 -path '/proc/[0-9]*/fd/*' \( -lname "$tmp*" -o -lname "$real*" \)
    } 2>/dev/null | sed 's#/proc/\([0-9]*\)/.*#\1#' | sort -u)
    [ "${#pids[@]}" -eq 0 ] || kill "${pids[@]}" 2>/dev/null || true
    [ "${#pids[@]}" -ne 0 ]
}

# A broken sweep answers "no survivors" too, and one working carrier answers for three broken ones,
# so each gets a decoy holding it alone — rescanned, not slept on, being invisible until it execs.
control() {
    for _ in 1 2 3 4 5; do
        outlived_the_gate && return 0
    done
    fail "a process holding the workspace only $1 outlives the gate unseen"
}

( cd / && exec env -i HOLD="$tmp" sleep 60 ) >/dev/null 2>&1 &
control "in its environment"
( cd / && exec env -i sh -c ": $tmp; sleep 60; :" ) >/dev/null 2>&1 &
control "on its command line"
( cd "$tmp" && exec env -i sleep 60 ) >/dev/null 2>&1 &
control "as its directory"
( cd / && exec env -i sleep 60 9<"$tmp/lockfile" ) >/dev/null 2>&1 &
control "as an open descriptor"

# Both accepted codes: blanking the results on the one meaning "found" closes the open alerts.
for code in 0 1; do
    if ! run_gate "$code"; then
        fail "a scanner exit of $code should pass the job, because the scan happened"
    elif [ "$(grep -c '^CALL$' "$tmp/argv")" != 1 ]; then
        fail "on exit $code the gate ran docker $(grep -c '^CALL$' "$tmp/argv") times, and only one call is pinned below"
    elif ! cmp -s "$tmp/work/results.sarif" "$tmp/sarif"; then
        fail "on exit $code the results file is not what the scanner wrote by the time the gate passed it"
    elif ! cmp -s "$tmp/lockfile-seen" "$tmp/lockfile"; then
        fail "on exit $code the scanner did not read the job's lockfile at the path the argv pins"
    elif [ -L "$tmp/work/results.sarif" ] || [ -e "$tmp/elsewhere" ]; then
        fail "on exit $code the results were written through a link left at their path"
    elif [ "$(out_mount | wc -l)" != 1 ]; then
        fail "on exit $code the scanner was given $(out_mount | wc -l) output mounts, and one is asserted below"
    elif ! outside_the_workspace "$(out_mount)"; then
        fail "on exit $code the scanner could write to $(out_mount), which is not outside the workspace"
    elif [ -e "$tmp/work/decoy" ] || [ -e "$tmp/work/.git" ]; then
        fail "on exit $code something the scanner wrote beside the results crossed into the workspace"
    elif [ -d "$(out_mount)" ]; then
        fail "on exit $code the scanner's output directory outlived the gate"
    elif outlived_the_gate; then
        fail "on exit $code the gate left work running, which can still reach the results it passed on"
    fi
done

for code in $(seq 2 255); do
    if run_gate "$code"; then
        fail "a scanner exit of $code passed the job, but the results cannot be trusted"
    elif ! grep -q "::error::OSV-Scanner exited $code" "$tmp/out"; then
        fail "a scanner exit of $code failed the job without annotating the run"
    elif [ -d "$(out_mount)" ]; then
        fail "a scanner exit of $code left the output directory behind"
    fi
done

printf 'PRIVATE TO THE RUNNER\n' >"$tmp/private"
for leaves in link nothing; do
    if run_gate 0 "$leaves"; then
        fail "a scanner that left $leaves in place of its results passed the job"
    elif ! grep -q "::error::" "$tmp/out"; then
        fail "a scanner that left $leaves in place of its results failed without saying so"
    elif cmp -s "$tmp/work/results.sarif" "$tmp/private"; then
        fail "the scanner named a file of the runner's and the gate filed it as the scan"
    elif [ -d "$(out_mount)" ]; then
        fail "a scanner that left $leaves in place of its results left the output directory behind"
    fi
done

# cp refuses a dangling link and writes through a live one, so only the removal covers both.
printf 'BESIDE THE WORKSPACE\n' >"$tmp/live"
if ! run_gate 0 results "$tmp/live"; then
    fail "a live link at the results path failed the job"
elif ! cmp -s "$tmp/work/results.sarif" "$tmp/sarif"; then
    fail "with a live link at the results path the results are not what the scanner wrote"
elif [ "$(cat "$tmp/live")" != "BESIDE THE WORKSPACE" ]; then
    fail "the results were written through a live link, into a file outside the workspace"
fi

run_gate 0 || fail "the gate failed on exit 0, so the output directory below is not one a pass makes"
first=$(out_mount)
run_gate 0 || fail "the gate failed on exit 0 the second time"
[ "$first" != "$(out_mount)" ] ||
    fail "the scanner's output directory is $first on both runs, so a link can be waiting at it"

# In order and entire: the scanner takes the last --config it is given.
run_gate 0 || fail "the gate failed on exit 0, so the pinned argv below is not what a pass sends"
expected=$(printf '%s\n' CALL run --rm --user "$(id -u):$(id -g)" \
    --volume "$tmp/work/Cargo.lock:/scan/Cargo.lock:ro" --volume "OUT:/out" --workdir /scan \
    "$SCANNER_PIN" scan source --config=/dev/null --lockfile=/scan/Cargo.lock --format=sarif \
    --output-file=/out/results.sarif)
seen=$(sed 's#^/.*:/out$#OUT:/out#' "$tmp/argv")
if [ "$seen" != "$expected" ]; then
    fail "docker is not invoked with exactly the pinned arguments:"
    diff <(printf '%s\n' "$expected") <(printf '%s\n' "$seen") | sed 's/^/    /'
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures assertion(s) failed"
    exit 1
fi
echo ok
