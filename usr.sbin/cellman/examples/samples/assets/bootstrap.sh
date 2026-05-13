#!/bin/sh
set -eu

echo "sample bootstrap in ${CELL_NAME:-unknown} (manifest dir: ${MANIFEST_DIR:-unknown})"
if [ "${1:-}" = "--mode" ] && [ -n "${2:-}" ]; then
	echo "mode=${2}"
fi

if [ -n "${OUTPUT_FILE:-}" ]; then
  printf "cell=%s\nmanifest_dir=%s\nmode=%s\n" \
      "${CELL_NAME:-unknown}" \
      "${MANIFEST_DIR:-unknown}" \
      "${2:-unknown}" > "${OUTPUT_FILE}"
fi
