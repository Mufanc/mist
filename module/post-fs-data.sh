set -eu

MODDIR=${0%/*}
MIST_BINARY="$MODDIR/bin/mist"

chmod 744 "$MIST_BINARY"
RUST_LOG="debug" LOGCAT="1" "$MIST_BINARY" inject "$MODDIR/bin/libmist.so" &
