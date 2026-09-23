#!/bin/sh
# Crack a password hash or a KeePass database with John the Ripper (jumbo). A hash comes from
# --hash (typically a value from `searu loot`); a KeePass/Office/zip file comes from --file and is
# converted to a hash first. Recovered plaintext is printed as `CRACKED hash=<h> password=<p>` lines
# for the wrapper to normalise; everything else is noise on stderr.
set -eu

JOHN=/opt/john/run/john
K2J=/opt/john/run/keepass2john

HASH=""
FILE=""
FORMAT="raw-md5"
WORDLIST=""
RULES=""
while [ $# -gt 0 ]; do
    case "$1" in
        --hash) HASH="$2"; shift 2 ;;
        --file) FILE="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        --wordlist) WORDLIST="$2"; shift 2 ;;
        --rules) RULES="$2"; shift 2 ;;
        *) shift ;;
    esac
done

work=$(mktemp -d)
hashfile="$work/hashes"
if [ -n "$FILE" ]; then
    if [ ! -x "$K2J" ]; then
        echo "crack: keepass2john not found at $K2J (this john build lacks it)" >&2
        exit 3
    fi
    # Surface keepass2john's real error (unsupported KDBX version, keyfile-protected DB, …) instead of
    # hiding it and feeding John a raw binary blob that yields a misleading "No password hashes loaded".
    if ! "$K2J" "$FILE" > "$hashfile" 2>"$work/k2j.err" || [ ! -s "$hashfile" ]; then
        echo "crack: keepass2john could not convert $FILE:" >&2
        cat "$work/k2j.err" >&2
        exit 3
    fi
    FORMAT=""
elif [ -n "$HASH" ]; then
    printf '%s\n' "$HASH" > "$hashfile"
else
    echo "crack: provide --hash <hash> or --file <path>" >&2
    exit 2
fi

fmt=""
[ -n "$FORMAT" ] && fmt="--format=$FORMAT"
wl=""
[ -n "$WORDLIST" ] && wl="--wordlist=$WORDLIST"
# Mangle the wordlist with a John rule set (e.g. best64, jumbo) to reach passwords a plain list misses.
rules=""
[ -n "$RULES" ] && rules="--rules=$RULES"

# shellcheck disable=SC2086
"$JOHN" $fmt $wl $rules "$hashfile" >&2 2>&1 || true
# shellcheck disable=SC2086
"$JOHN" --show $fmt "$hashfile" 2>/dev/null | while IFS= read -r line; do
    case "$line" in
        "" | *"password hash"* | *"password hashes"* | *"0 password"*) ;;
        *:*) printf 'CRACKED hash=%s password=%s\n' "${HASH:-?}" "${line#*:}" ;;
    esac
done
