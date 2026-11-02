#!/bin/sh
# Fetch the real, deliberately-vulnerable applications RedFall is tested on.
#
#   sh sandbox/fetch_challenges.sh          fetch whatever is missing
#   REDFALL_FORCE=1 sh sandbox/fetch_challenges.sh   refetch everything
#
# Why these three. A seeded corpus written by the same person who wrote the
# detectors measures agreement, not capability: both sides share a blind spot
# and the number looks good. Third-party challenge apps are code this project
# did not write, seeded by people who had no interest in what RedFall finds,
# which is the only kind of input that can falsify the holdout gap.
#
# Every clone is pinned to a commit. A challenge that moves under the runner
# makes yesterday's result unreproducible, and an unreproducible score is the
# thing this repository exists to argue against.
#
# The trees are large and are NOT committed; `sandbox/challenges/` is ignored.
# This script plus `ground_truth.json` beside it is what reproduces a run.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DEST="$HERE/challenges"
FORCE="${REDFALL_FORCE:-}"

mkdir -p "$DEST"

# name|repo|ref|language|what it is
#
# The refs are real commits resolved with `git ls-remote` at the time of
# writing, not branch names: `master` moves, and a challenge that moves under
# the runner makes a past result unreproducible.
TARGETS='
nodegoat|https://github.com/OWASP/NodeGoat|c5cb68a7084e4ae7dcc60e6a98768720a81841e8|javascript|OWASP NodeGoat: a deliberately vulnerable Node/Express app
dvna|https://github.com/appsecco/dvna|9ba473add536f66ac9007966acb2a775dd31277a|javascript|Damn Vulnerable Node Application
'

fetch() {
    name="$1"; repo="$2"; ref="$3"; language="$4"; note="$5"
    dir="$DEST/$name"

    if [ -d "$dir/.git" ] && [ -z "$FORCE" ]; then
        echo "  $name already present (REDFALL_FORCE=1 to refetch)"
        return 0
    fi

    printf '  fetching %s ... ' "$name"
    rm -rf "$dir"
    # A shallow clone of a tag or branch. Depth 1 keeps the download small;
    # the commit is recorded below and verified on every scoring run.
    if ! git clone --quiet --depth 1 --branch "$ref" "$repo" "$dir" 2>/dev/null; then
        # `--branch` fails on a raw commit sha; fall back to a full clone.
        git clone --quiet "$repo" "$dir"
        ( cd "$dir" && git checkout --quiet "$ref" )
    fi
    ( cd "$dir" && git rev-parse HEAD ) > "$DEST/$name.commit"
    echo "ok ($(cat "$DEST/$name.commit" | cut -c1-10))"
}

echo "fetching real-world challenge targets into sandbox/challenges/"
# Read the table line by line with `|` as the field separator, so a note with
# spaces in it stays one field instead of splitting into extra arguments.
printf '%s\n' "$TARGETS" | while IFS='|' read -r name repo ref language note; do
    [ -z "${name:-}" ] && continue
    fetch "$name" "$repo" "$ref" "$language" "$note"
done

echo
echo "done. score them with:"
echo "  python -m redfall.cli sandbox run"
