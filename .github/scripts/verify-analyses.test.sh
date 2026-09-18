#!/usr/bin/env bash
# Without this the checker could be reduced to an exit 0 and nobody would be told. The workflow's
# launch is reproduced — same relative path, same job environment, the same variables set and unset
# — because a body that can tell a test from a runner can behave differently in each. The set of
# things it could look at is not closed, so this narrows the gap.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/work/.github/scripts"
failures=0
SHA=e6efee073fb50d15e4a14d174b71d5004a130ea7
WANT="/language:rust /language:c-cpp osv-scanner"

fail() {
    echo "  $1"
    failures=$((failures + 1))
}

cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
[ -n "${FAIL_ALWAYS:-}" ] && { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
[ -n "${FAIL_ONCE:-}" ] && [ ! -f "$STATE" ] && { : >"$STATE"; echo "Server Error (HTTP 502)" >&2; exit 1; }
query=""
paginate=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        --jq) query=$2; shift 2 ;;
        --paginate) paginate=yes; shift ;;
        *) url=$1; shift ;;
    esac
done
printf '%s' "$url" >"$URL_SEEN"
# The endpoint answers for the ref it was asked about, and for every ref if it was asked about none.
filter=""
if [ "$url" != "${url#*ref=}" ]; then
    ref=${url##*ref=}
    filter="map(select(.ref == \"${ref%%&*}\")) | "
fi
for page in $FIXTURE; do
    jq -r "$filter$query" "$page"
    [ -n "$paginate" ] || break
done
EOF
chmod +x "$tmp/bin/gh"

printf '#!/usr/bin/env bash\nexit 0\n' >"$tmp/bin/sleep"
chmod +x "$tmp/bin/sleep"

OTHER=0000000000000000000000000000000000000000
seq=0

# The whole object the API returns: a filter widened to a field the checker does not read today is
# invisible to a fixture that carries only the two it does.
analysis() {
    local tool=osv-scanner job=osv env='{}' ref=${3:-$REF_SHAPE}
    case "$2" in /language:*) tool=CodeQL job=codeql env='{\"language\":\"'${2#/language:}'\"}' ;; esac
    seq=$((seq + 1))
    printf '{"id":%s,"ref":"%s","commit_sha":"%s","analysis_key":".github/workflows/security.yml:%s",
      "category":"%s","created_at":"2026-09-18T00:00:00Z","results_count":0,"rules_count":42,
      "tool":{"name":"%s","guid":null,"version":"2.23.2"},"deletable":true,"warning":"",
      "sarif_id":"sarif-%s","environment":"%s",
      "url":"https://api.github.com/repos/e2b-dev/userfaultfd-rs/code-scanning/analyses/%s"}' \
        "$seq" "$ref" "$1" "$job" "$2" "$tool" "$seq" "$env" "$seq"
}

page() {
    local out=$1 sep="" pair sha category ref
    shift
    : >"$out"
    printf '[' >>"$out"
    for pair in "$@"; do
        IFS='|' read -r sha category ref <<<"$pair"
        printf '%s' "$sep" >>"$out"
        analysis "$sha" "$category" "$ref" >>"$out"
        sep=","
    done
    printf ']' >>"$out"
}

analyses() {
    page "$tmp/fixture.json" "$@"
    pages="$tmp/fixture.json"
}

run_check() {
    cp "$here/verify-analyses.sh" "$tmp/work/.github/scripts/verify-analyses.sh"
    rm -f "$tmp/url-seen"
    (cd "$tmp/work" && PATH="$tmp/bin:$PATH" env FIXTURE="$pages" STATE="$tmp/state" \
        URL_SEEN="$tmp/url-seen" "$@" \
        GITHUB_ACTIONS=true GITHUB_WORKFLOW=security GITHUB_JOB=verify GH_TOKEN=token \
        GITHUB_REPOSITORY=e2b-dev/userfaultfd-rs REF="$REF_SHAPE" SHA="$SHA" EXPECTED="$WANT" \
        bash .github/scripts/verify-analyses.sh) >"$tmp/out" 2>&1
}

check_verdict() {
    local name="$1 on $REF_SHAPE" want_rc=$2
    rm -f "$tmp/state"
    if run_check; then
        [ "$want_rc" = 0 ] || fail "$name: passed, and it should not have"
    else
        [ "$want_rc" = 1 ] || fail "$name: failed, and it should not have — $(cat "$tmp/out")"
        grep -q "::error::" "$tmp/out" || fail "$name: failed without an annotation naming what was missing"
    fi
}

# Both shapes the workflow runs under: a body that reads the ref can pass one and skip the other.
for REF_SHAPE in refs/pull/1/merge refs/heads/feat_write_protection; do
    three=("$SHA|/language:rust" "$SHA|/language:c-cpp" "$SHA|osv-scanner")

    analyses "${three[@]}"
    check_verdict "exactly the expected categories" 0

    want_url="repos/e2b-dev/userfaultfd-rs/code-scanning/analyses?ref=$REF_SHAPE&per_page=100"
    [ "$(cat "$tmp/url-seen")" = "$want_url" ] ||
        fail "the check asks for $(cat "$tmp/url-seen"), not $want_url"

    analyses "$SHA|/language:rust" "$SHA|osv-scanner"
    check_verdict "a missing category" 1

    page "$tmp/page1.json" "$SHA|/language:rust"
    page "$tmp/page2.json" "$SHA|/language:c-cpp" "$SHA|osv-scanner"
    pages="$tmp/page1.json $tmp/page2.json"
    check_verdict "the expected categories spread over two pages" 0

    # At each end of the sort order: a tolerant comparison usually tolerates one end only.
    for extra in "/language:actions" "/language:go" "zzz-other-tool"; do
        analyses "${three[@]}" "$SHA|$extra"
        check_verdict "an unexpected category, $extra" 1
    done

    analyses "$OTHER|/language:rust" "$OTHER|/language:c-cpp" "$OTHER|osv-scanner"
    check_verdict "the right categories on another commit" 1

    analyses "$OTHER|/language:rust" "$OTHER|/language:c-cpp" "$SHA|osv-scanner"
    check_verdict "the CodeQL categories filed by an earlier commit" 1

    analyses "$SHA|/language:rust" "$SHA|/language:c-cpp" "$OTHER|osv-scanner"
    check_verdict "the scanner category filed by an earlier commit" 1

    analyses "$SHA|/language:rust|refs/heads/other" "$SHA|/language:c-cpp|refs/heads/other" \
        "$SHA|osv-scanner|refs/heads/other"
    check_verdict "the expected categories filed on another ref" 1

    analyses
    check_verdict "no analyses at all" 1

    analyses "${three[@]}"
    rm -f "$tmp/state"
    if ! run_check FAIL_ONCE=1; then
        fail "a single API error ended the run instead of being retried — $(cat "$tmp/out")"
    fi

    if run_check FAIL_ALWAYS=1; then
        fail "an API that never answered passed the job — $(cat "$tmp/out")"
    elif ! grep -q "never answered" "$tmp/out"; then
        fail "an API that never answered is reported as an empty set of analyses"
    fi
done

if [ "$failures" -ne 0 ]; then
    echo "$failures assertion(s) failed"
    exit 1
fi
echo ok
