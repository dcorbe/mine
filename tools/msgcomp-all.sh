#!/usr/bin/env bash
# Compile every .MSG in the current directory into the .MCV beside it.
#
# Galacticomm shipped compilation as a separate operator step, never something
# the host does at boot -- `WGSMSX.EXE` on Worldgroup, `MSGCOMP` on DOS, and
# neither survives in the recovered archive. A module's .MSG is the source; the
# host and every offline utility read only the compiled .MCV. `WCCMMUTL.EXE`
# refuses to start without one ("CANNOT FIND \"WCCMMUD.MCV\"").
#
# A MajorMUD tree needs three or four of these compiled together (WCCMMUD,
# WCCMMHLP, WCCTEXT, and WCCMMPLS if the Plus module is installed), which is
# why this exists rather than four msgcomp invocations by hand.
#
# Usage:  cd /path/to/board-data && tools/msgcomp-all.sh
#         MSGCOMP=/some/other/msgcomp tools/msgcomp-all.sh
#
# Operates on the current directory only, never recursively -- a board tree has
# .MSG files under subdirectories that belong to other modules, and compiling
# those silently would put a stale .MCV somewhere nobody looked.

set -euo pipefail

# Resolve msgcomp from the repo this script lives in, so the script works from
# any cwd -- which is the whole point, since it is meant to be run inside a
# board data directory rather than inside the repo.
if [[ -n "${MSGCOMP:-}" ]]; then
    if [[ ! -x "$MSGCOMP" ]]; then
        echo "msgcomp-all: MSGCOMP=$MSGCOMP is not executable" >&2
        exit 1
    fi
    msgcomp="$MSGCOMP"
else
    root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
    msgcomp=""
    for candidate in "$root/target/release/msgcomp" "$root/target/debug/msgcomp"; do
        if [[ -x "$candidate" ]]; then
            msgcomp="$candidate"
            break
        fi
    done
    if [[ -z "$msgcomp" ]]; then
        msgcomp="$(command -v msgcomp || true)"
    fi
    if [[ -z "$msgcomp" ]]; then
        echo "msgcomp-all: no msgcomp binary found." >&2
        echo "  build one with: cargo build --release -p mbbs --bin msgcomp" >&2
        echo "  or point MSGCOMP at an existing one." >&2
        exit 1
    fi
fi

# NUL-delimited, because a board directory is period data and its filenames are
# not guaranteed to be well behaved. -maxdepth 1 keeps this to the cwd; -iname
# catches both WCCMMUD.MSG and wccmmud.msg, which real trees mix freely.
mapfile -d '' -t sources < <(find . -maxdepth 1 -type f -iname '*.msg' -print0 | sort -z)

# Doing nothing is a result worth reporting, not a silent success -- running
# this in the wrong directory should be loud.
if [[ ${#sources[@]} -eq 0 ]]; then
    echo "msgcomp-all: no .MSG files in $(pwd)" >&2
    exit 1
fi

failed=0
compiled=0
for src in "${sources[@]}"; do
    src="${src#./}"
    if "$msgcomp" "$src"; then
        compiled=$((compiled + 1))
    else
        # Keep going: one malformed .MSG should not stop the other three from
        # compiling, and the exit status still reports the failure.
        echo "msgcomp-all: FAILED $src" >&2
        failed=$((failed + 1))
    fi
done

echo "msgcomp-all: $compiled compiled, $failed failed"
[[ $failed -eq 0 ]]
