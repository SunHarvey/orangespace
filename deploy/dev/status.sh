#!/bin/sh
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
: "${ORANGESPACE_CONSOLE_SCOPE:?set a dedicated private scope directory}"
exec python3 "$here/console.py" --scope "$ORANGESPACE_CONSOLE_SCOPE" status "$@"
