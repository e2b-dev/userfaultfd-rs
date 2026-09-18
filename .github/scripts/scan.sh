#!/usr/bin/env bash
# The exit code is the verdict, not the results file: an unreachable api.osv.dev still writes a
# well-formed zero-result SARIF, and uploading that files a clean analysis of the branch.
set -euo pipefail

SCANNER=${SCANNER:?the scanner image must be pinned by digest}
LOCKFILE=${LOCKFILE:-./Cargo.lock}
OUTPUT=${OUTPUT:-results.sarif}
WORKSPACE=${GITHUB_WORKSPACE:-$PWD}

status=0
# --config, because an osv-scanner.toml committed beside the lockfile turns a real scan into a
# clean one. Unwrapped, because the published action pins its image by tag rather than digest.
docker run --rm --volume "$WORKSPACE:$WORKSPACE" --workdir "$WORKSPACE" "$SCANNER" \
    scan source \
    --config=/dev/null \
    --lockfile="$LOCKFILE" \
    --format=sarif \
    --output-file="$OUTPUT" || status=$?

case "$status" in
    0 | 1) ;;
    *)
        echo "::error::OSV-Scanner exited $status; its results are not trustworthy"
        exit 1
        ;;
esac
