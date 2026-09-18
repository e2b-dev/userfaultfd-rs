#!/usr/bin/env bash
# The workflow's launch is reproduced — same relative path, same job environment, docker stubbed on
# PATH rather than named — because a body that can tell the two apart can behave differently in each.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/work/.github/scripts"
failures=0
SCANNER_PIN="ghcr.io/google/osv-scanner@sha256:afd838850ac1a0fcc15ff4a041dc9ba11123c3f0d2666217a5f0fcf9222b55fa"

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
printf '%s\n' "\$@" >"$tmp/argv"
cat ./Cargo.lock >"$tmp/lockfile-seen" 2>/dev/null || printf 'MISSING' >"$tmp/lockfile-seen"
for arg in "\$@"; do
    case "\$arg" in --output-file=*)
        out=\${arg#--output-file=}
        [ -L "\$out" ] && printf 'symlink' >"$tmp/output-kind"
        cp "$tmp/sarif" "\$out" ;;
    esac
done
exit $1
EOF
    chmod +x "$tmp/bin/docker"
}

run_gate() {
    stub "$1"
    cp "$tmp/lockfile" "$tmp/work/Cargo.lock"
    printf '[package]\n' >"$tmp/work/Cargo.toml"
    rm -f "$tmp/output-kind"
    cp "$here/scan.sh" "$tmp/work/.github/scripts/scan.sh"
    (cd "$tmp/work" && PATH="$tmp/bin:$PATH" SCANNER="$SCANNER_PIN" GITHUB_WORKSPACE="$tmp/work" \
        GITHUB_ACTIONS=true GITHUB_WORKFLOW=security GITHUB_JOB=osv \
        bash .github/scripts/scan.sh) >"$tmp/out" 2>&1
    local rc=$?
    # A detached child leaves the gate's process group. It cannot leave the workspace behind: to
    # write these results later it has to carry the path, in its environment, on its command line or
    # as its directory. A writer that hides it in a file of its own is still not reached.
    mapfile -t survivors < <({
        grep -la "$tmp" /proc/[0-9]*/environ /proc/[0-9]*/cmdline
        find /proc -maxdepth 2 -name cwd -lname "$tmp*"
    } 2>/dev/null | sed 's#/proc/\([0-9]*\)/.*#\1#' | sort -u)
    [ "${#survivors[@]}" -eq 0 ] || kill "${survivors[@]}" 2>/dev/null || true
    return "$rc"
}

# Both accepted codes: blanking the results on the one meaning "found" closes the open alerts.
for code in 0 1; do
    if ! run_gate "$code"; then
        fail "a scanner exit of $code should pass the job, because the scan happened"
    elif ! cmp -s "$tmp/work/results.sarif" "$tmp/sarif"; then
        fail "on exit $code the results file is not what the scanner wrote by the time the gate passed it"
    elif ! cmp -s "$tmp/lockfile-seen" "$tmp/lockfile"; then
        fail "on exit $code the scanner read a lockfile that is not the one the job checked out"
    elif [ -e "$tmp/output-kind" ]; then
        fail "on exit $code the scanner was pointed at a symlink, so its results are written elsewhere"
    elif [ "${#survivors[@]}" -ne 0 ]; then
        fail "on exit $code the gate left work running, which can still reach the results it passed on"
    fi
done

# The complement, not a sample: a widened pattern is invisible to a short list.
for code in $(seq 2 255); do
    if run_gate "$code"; then
        fail "a scanner exit of $code passed the job, but the results cannot be trusted"
    elif ! grep -q "exited $code" "$tmp/out"; then
        fail "a scanner exit of $code failed the job without saying so"
    fi
done

# In order and entire: the scanner takes the last --config it is given.
run_gate 0
expected=$(printf '%s\n' run --rm --volume "$tmp/work:$tmp/work" --workdir "$tmp/work" \
    "$SCANNER_PIN" scan source --config=/dev/null --lockfile=./Cargo.lock --format=sarif \
    --output-file=results.sarif)
if [ "$(cat "$tmp/argv")" != "$expected" ]; then
    fail "docker is not invoked with exactly the pinned arguments:"
    diff <(printf '%s\n' "$expected") "$tmp/argv" | sed 's/^/    /'
fi

if [ "$failures" -ne 0 ]; then
    echo "$failures assertion(s) failed"
    exit 1
fi
echo ok
