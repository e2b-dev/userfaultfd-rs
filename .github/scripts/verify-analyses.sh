#!/usr/bin/env bash
# Reading the workflow cannot see a scan that uploaded nothing, or one whose category merged
# with another tool's and closed the alerts behind it.
set -euo pipefail

REPO=${GITHUB_REPOSITORY:?}
REF=${REF:?}
SHA=${SHA:?}
EXPECTED=${EXPECTED:?the categories that must exist, space separated}
# Indexing is asynchronous, so absence is only absence once it has had time to appear.
ATTEMPTS=${ATTEMPTS:-10}
PAUSE=${PAUSE:-15}

# shellcheck disable=SC2086  # EXPECTED is a list; splitting it is what turns it into lines.
want=$(printf '%s\n' ${EXPECTED} | sort -u | tr '\n' ' ' | sed 's/ $//')
found=""
answered=""

for attempt in $(seq "$ATTEMPTS"); do
    # Paginated: the ref lists every analysis ever filed on it, and one page is a truncated answer.
    if found=$(gh api --paginate "repos/$REPO/code-scanning/analyses?ref=$REF&per_page=100" \
        --jq ".[] | select(.commit_sha == \"$SHA\") | .category" | sort -u | tr '\n' ' ' | sed 's/ $//'); then
        answered=yes
    else
        found=""
    fi
    [ "$found" = "$want" ] && break
    [ "$attempt" = "$ATTEMPTS" ] || sleep "$PAUSE"
done

if [ "$found" != "$want" ]; then
    [ -n "$answered" ] || echo "::error::the code scanning API never answered for $SHA on $REF"
    echo "::error::$SHA on $REF carries analyses under [$found], not [$want]"
    exit 1
fi
echo "ok: $want, all on $SHA"
