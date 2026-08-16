#!/usr/bin/env bash
# Serve LORD to Synchronet through the dos-poc runtime instead of dosemu.
#
# Synchronet runs this under forkpty() with XTRN_NATIVE|XTRN_STDIO, so our
# stdin and stdout are the user's telnet session. The runtime turns that into a
# COM1 the DOS program can drive, which is what LORD in door mode expects: it
# programs the 8250 directly rather than using int 14h or a FOSSIL driver.
#
#   cmd      = /sbbs/xtrn/lord/lord-dospoc.sh %#
#   type     = 3        (DOOR.SYS dropfile)
#   settings = 16388    (XTRN_NATIVE | XTRN_STDIO)
#
# Everything is overridable so this can be exercised away from a live board.
set -uo pipefail

NODE="${1:-1}"
LORD_DIR="${LORD_DIR:-/sbbs/xtrn/lord}"
NODE_DIR="${SBBS_NODE_DIR:-/sbbs/node${NODE}}"
RUNEXE="${RUNEXE:-/sbbs/xtrn/lord/runexe}"

DROP_SRC="$NODE_DIR/DOOR.SYS"
DROP_DIR="$LORD_DIR/NODE${NODE}"
DROP="$DROP_DIR/DOOR.SYS"

[ -r "$DROP_SRC" ] || { echo "LORD: no DOOR.SYS at $DROP_SRC"; sleep 2; exit 1; }
mkdir -p "$DROP_DIR"

# LORD is a Turbo Pascal program reading a DOS text file: the line endings have
# to be CRLF, and a blank line where it expects a field is not the same as a
# field it can parse. The same massaging the dosemu wrapper does, for the same
# reason.
awk '/^[[:space:]]*$/ { printf "NONE\r\n"; next }
     { sub(/\r$/, ""); printf "%s\r\n", $0 }' "$DROP_SRC" > "$DROP"

# LORD's own START.BAT loops here: exit code 254 means "run the in-game module
# I just wrote a batch file for, then come back". We do not run IGMs yet, so
# the loop is honest about stopping rather than silently dropping the player
# back to the BBS as though the game had ended.
while : ; do
    "$RUNEXE" "$LORD_DIR/LORD.EXE" \
        --root "$LORD_DIR" \
        --door \
        --dropfile "$DROP" \
        "$NODE" /DREW
    rc=$?
    case "$rc" in
        254)
            if [ -r "$LORD_DIR/DO${NODE}.BAT" ]; then
                echo -e "\r\n[in-game modules are not supported by this runtime yet]\r"
                sleep 2
            fi
            break
            ;;
        *) break ;;
    esac
done

# INFO.n and DO<n>.BAT are LORD's scratch for the session; leaving them behind
# confuses the next player on this node.
rm -f "$LORD_DIR/INFO.${NODE}" "$LORD_DIR/DO${NODE}.BAT"
exit "$rc"
