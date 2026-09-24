#!/usr/bin/env bash
# The exit code is the verdict, not the results file's content: an unreachable api.osv.dev still writes a
# well-formed zero-result SARIF, and uploading that files a clean analysis of the branch.
set -euo pipefail

SCANNER=${SCANNER:?the scanner image must be pinned by digest}
LOCKFILE=Cargo.lock
OUTPUT=results.sarif
WORKSPACE=${GITHUB_WORKSPACE:-$PWD}

out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

status=0
# Only the lockfile goes in, so a committed osv-scanner.toml never reaches the scan; --config holds
# if that widens. Unwrapped, because the published action pins its image by tag rather than digest.
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "$WORKSPACE/$LOCKFILE:/scan/$LOCKFILE:ro" \
    --volume "$out:/out" \
    --workdir /scan \
    "$SCANNER" \
    scan source \
    --config=/dev/null \
    --lockfile="/scan/$LOCKFILE" \
    --format=sarif \
    --output-file="/out/$OUTPUT" || status=$?

case "$status" in
    0 | 1) ;;
    *)
        echo "::error::OSV-Scanner exited $status; its results are not trustworthy"
        exit 1
        ;;
esac

# The image chooses what it leaves in its output directory, so what is copied out has to be a file
# the scanner wrote rather than a link it aimed at one of the runner's.
if [ ! -f "$out/$OUTPUT" ] || [ -L "$out/$OUTPUT" ]; then
    echo "::error::OSV-Scanner exited $status leaving no results of its own at $OUTPUT"
    exit 1
fi

# Removed rather than written through, so a link left at the path does not redirect the results.
rm -f "${WORKSPACE:?}/$OUTPUT"
cp "$out/$OUTPUT" "$WORKSPACE/$OUTPUT"
