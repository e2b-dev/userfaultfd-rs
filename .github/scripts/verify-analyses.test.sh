#!/usr/bin/env bash
# The checker's verdict against the answers the code-scanning API really gives. It cannot speak to a
# body written to recognise this launch and skip in the job.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/work/.github/scripts"
failures=0
SHA=e6efee073fb50d15e4a14d174b71d5004a130ea7
WANT="/language:rust /language:c-cpp osv-scanner"
# Varied at the end, so a body that reads none of the three and hardcodes what this repository
# happens to ship still has to answer for a different one.
REPO=e2b-dev/userfaultfd-rs

fail() {
    echo "  $1"
    failures=$((failures + 1))
}

printf '#!/usr/bin/env bash\ntmp=%q\n' "$tmp" >"$tmp/bin/gh"
cat >>"$tmp/bin/gh" <<'EOF'
printf 'x' >>"$tmp/calls"
[ -n "${FAIL_ALWAYS:-}" ] && { echo "HTTP 403: Resource not accessible by integration" >&2; exit 1; }
[ -n "${FAIL_ONCE:-}" ] && [ ! -f "$tmp/state" ] && { : >"$tmp/state"; echo "Server Error (HTTP 502)" >&2; exit 1; }
[ -n "${FAIL_AFTER:-}" ] && { [ -f "$tmp/state" ] && { echo "Server Error (HTTP 502)" >&2; exit 1; }; : >"$tmp/state"; }
query=""
paginate=""
url=""
while [ $# -gt 0 ]; do
    case "$1" in
        --jq) query=$2; shift 2 ;;
        --paginate) paginate=yes; shift ;;
        -*) echo "unrecognised flag $1" >&2; exit 1 ;;
        *) url=$1; shift ;;
    esac
done
printf '%s' "$url" >"$tmp/url-seen"
late=""
# The line the checker asks for, which is the JSON form: dropping the raw one would drop nothing.
if [ -n "${INDEXING:-}" ] && [ ! -f "$tmp/state.indexing" ]; then : >"$tmp/state.indexing"; late='"/language:c-cpp"'; fi
# The endpoint answers for the ref it was asked about, and for every ref if it was asked about none.
filter=""
if [ "$url" != "${url#*ref=}" ]; then
    ref=${url##*ref=}
    filter="map(select(.ref == \"${ref%%&*}\")) | "
fi
while IFS= read -r page; do
    jq -r "$filter$query" "$page"
    [ -n "$paginate" ] || break
done <<<"$FIXTURE" | awk -v late="$late" 'late == "" || $0 != late'
EOF
chmod +x "$tmp/bin/gh"

# Recorded, not taken: an interval that shrinks to nothing calls indexing late an absence.
printf '#!/usr/bin/env bash\nslept=%q\n' "$tmp/slept" >"$tmp/bin/sleep"
cat >>"$tmp/bin/sleep" <<'EOF'
printf '%s ' "$1" >>"$slept"
EOF
chmod +x "$tmp/bin/sleep"

OTHER=0000000000000000000000000000000000000000
# Shares the first seven hex with SHA, which is as much as an abbreviation carries.
NEAR=e6efee0f1111111111111111111111111111111f
seq=0

# The whole object the API returns: a filter widened to a field the checker does not read today is
# invisible to a fixture that carries only the two it does.
analysis() {
    local tool=osv-scanner job=osv env='{}' ref=${3:-$REF_SHAPE}
    case "$2" in /language:*) tool=CodeQL job=codeql env='{\"language\":\"'${2#/language:}'\"}' ;; esac
    seq=$((seq + 1))
    printf '{"id":%s,"ref":"%s","commit_sha":"%s","analysis_key":".github/workflows/security.yml:%s",
      "category":"%s","created_at":"2026-09-18T00:00:00Z","results_count":0,"rules_count":42,
      "tool":{"name":"%s","guid":null,"version":"2.23.2"},"deletable":true,"warning":"","error":"",
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
    (cd "$tmp/work" && PATH="$tmp/bin:$PATH" env FIXTURE="$pages" "$@" GH_TOKEN=token \
        GITHUB_REPOSITORY="$REPO" REF="$REF_SHAPE" SHA="$SHA" EXPECTED="$WANT" \
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
        if grep -q "never answered" "$tmp/out"; then
            fail "$name: an API that did answer is reported as never having answered"
        fi
    fi
}

# Both shapes the workflow runs under: a body that reads the ref can pass one and skip the other.
for REF_SHAPE in refs/pull/1/merge refs/heads/feat_write_protection; do
    three=("$SHA|/language:rust" "$SHA|/language:c-cpp" "$SHA|osv-scanner")

    analyses "${three[@]}"
    check_verdict "exactly the expected categories" 0

    want_url="repos/$REPO/code-scanning/analyses?ref=$REF_SHAPE&per_page=100"
    [ "$(cat "$tmp/url-seen")" = "$want_url" ] ||
        fail "the check asks for $(cat "$tmp/url-seen"), not $want_url"

    analyses "$SHA|/language:rust" "$SHA|osv-scanner"
    check_verdict "a missing category" 1

    analyses "$SHA|osv-scanner" "$SHA|/language:c-cpp" "$SHA|/language:rust"
    check_verdict "the expected categories in another order" 0

    # Sorts where the expected one sorts, so only a comparison of the bytes tells them apart.
    analyses "$SHA|/language:rust" "$SHA|/language:c-cpp" "$SHA|OSV-Scanner"
    check_verdict "a category differing from the expected one only in case" 1

    # Same count, one of them wrong: a comparison that counts rather than compares passes this.
    for swap in "/language:actions" "zzz-other-tool"; do
        analyses "$SHA|/language:rust" "$SHA|/language:c-cpp" "$SHA|$swap"
        check_verdict "a category replaced by $swap" 1
    done

    analyses "${three[@]}" "${three[@]}"
    check_verdict "every category filed twice, as each scheduled run on an unmoved head does" 0

    page "$tmp/page1.json" "$SHA|/language:rust"
    page "$tmp/page2.json" "$SHA|/language:c-cpp" "$SHA|osv-scanner"
    pages="$tmp/page1.json"$'\n'"$tmp/page2.json"
    check_verdict "the expected categories spread over two pages" 0

    # Alongside the expected one rather than in its place, which a comparison folding case accepts.
    analyses "${three[@]}" "$SHA|OSV-Scanner"
    check_verdict "an unexpected category differing from an expected one only in case" 1

    # At each end of the sort order: a tolerant comparison usually tolerates one end only.
    for extra in "/language:actions" "/language:go" "zzz-other-tool"; do
        analyses "${three[@]}" "$SHA|$extra"
        check_verdict "an unexpected category, $extra" 1
    done

    analyses "$OTHER|/language:rust" "$OTHER|/language:c-cpp" "$OTHER|osv-scanner"
    check_verdict "the right categories on another commit" 1

    analyses "$NEAR|/language:rust" "$NEAR|/language:c-cpp" "$NEAR|osv-scanner"
    check_verdict "the right categories on a commit sharing seven hex with this one" 1

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
    analyses "${three[@]}"
    rm -f "$tmp/state" "$tmp/state.indexing" "$tmp/calls"
    if ! run_check INDEXING=1; then
        fail "a category indexed one attempt late is reported as missing — $(cat "$tmp/out")"
    elif calls=$(cat "$tmp/calls") && [ "$calls" != xx ]; then
        fail "the answer completed on the second call and the check asked ${#calls} times"
    fi

    analyses "${three[@]}"
    rm -f "$tmp/state"
    if ! run_check FAIL_ONCE=1; then
        fail "a single API error ended the run instead of being retried — $(cat "$tmp/out")"
    fi

    rm -f "$tmp/calls" "$tmp/slept"
    if run_check FAIL_ALWAYS=1; then
        fail "an API that never answered passed the job — $(cat "$tmp/out")"
    elif ! grep -q "never answered" "$tmp/out"; then
        fail "an API that never answered is reported as an empty set of analyses"
    elif calls=$(cat "$tmp/calls") && [ "${#calls}" != 10 ]; then
        fail "an API that never answered was asked ${#calls} times before the job gave up"
    elif [ "$(cat "$tmp/slept" 2>/dev/null)" != "15 15 15 15 15 15 15 15 15 " ]; then
        fail "ten attempts waited '$(cat "$tmp/slept" 2>/dev/null)' between them, not 15s nine times"
    fi

    analyses "$SHA|/language:rust" "$SHA|osv-scanner"
    rm -f "$tmp/state"
    if run_check FAIL_AFTER=1; then
        fail "an API that stopped answering passed the job — $(cat "$tmp/out")"
    elif ! grep -qF 'under ["/language:rust" "osv-scanner"]' "$tmp/out"; then
        fail "what the API answered before it failed is reported as if nothing was filed"
    fi

    # A category is free text, so one filed as the expected set joined up reads as the whole set to
    # a comparison that joins on a character the category may contain.
    analyses "$SHA|/language:c-cpp /language:rust osv-scanner"
    check_verdict "one analysis whose category is the expected set joined by spaces" 1

    analyses "$SHA|/language:c-cpp /language:rust" "$SHA|osv-scanner"
    check_verdict "two analyses, one carrying two of the expected categories" 1
done

# None of these is what this repository ships, so a body that reads none of them and answers with
# what it was built against is red here while every case above stays green.
REPO=other-org/other-repo
SHA=1111111111111111111111111111111111111111
WANT="/language:go osv-scanner"
REF_SHAPE=refs/heads/main

analyses "$SHA|/language:go" "$SHA|osv-scanner"
check_verdict "another repository, commit and expected set" 0
want_url="repos/$REPO/code-scanning/analyses?ref=$REF_SHAPE&per_page=100"
[ "$(cat "$tmp/url-seen")" = "$want_url" ] ||
    fail "for another repository the check asks for $(cat "$tmp/url-seen"), not $want_url"

analyses "$SHA|osv-scanner"
check_verdict "another repository with one of its categories missing" 1

if [ "$failures" -ne 0 ]; then
    echo "$failures assertion(s) failed"
    exit 1
fi
echo ok
