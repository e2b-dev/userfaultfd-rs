#!/usr/bin/env bash
# Reading the workflow cannot see a scan that uploaded nothing, or one whose category merged
# with another tool's so that both were filed as one.
set -euo pipefail

REPO=${GITHUB_REPOSITORY:?}
REF=${REF:?}
SHA=${SHA:?}
EXPECTED=${EXPECTED:?the categories that must exist, space separated}

oneline() { printf '%s' "$1" | tr '\n' ' '; }

# Compared as JSON text, because a category is free text: joined by any character a category may
# itself contain, one filed as "a b c" would read as three present and hide two missing.
read -ra expected <<<"$EXPECTED"
want=$(printf '"%s"\n' "${expected[@]}" | sort -u)
found=""
answered=""

# Both uploads wait for processing, but that wait gives up after about two and a half minutes and
# passes anyway, so this covers processing as well as listing lag. No run has needed a second
# attempt, which is why the one reached is printed rather than assumed.
for attempt in $(seq 10); do
    # The ref lists every analysis ever filed on it, and one page is a truncated answer.
    # A failed call says nothing about what is filed, so the last answer the API gave is kept.
    if page=$(gh api --paginate "repos/$REPO/code-scanning/analyses?ref=$REF&per_page=100" \
        --jq ".[] | select(.commit_sha == \"$SHA\") | .category | @json"); then
        found=$(printf '%s\n' "$page" | sort -u)
        answered=yes
    fi
    [ "$found" = "$want" ] && break
    [ "$attempt" = 10 ] || sleep 15
done

if [ "$found" != "$want" ]; then
    if [ -n "$answered" ]; then
        echo "::error::$SHA on $REF carries analyses under [$(oneline "$found")], not [$(oneline "$want")]"
    else
        echo "::error::the code scanning API never answered for $SHA on $REF, so what it carries is unknown"
    fi
    exit 1
fi
echo "ok: $(oneline "$want"), all on $SHA, at attempt $attempt"
