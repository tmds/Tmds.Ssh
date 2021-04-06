#!/bin/bash

set -e

# Use docker instead of podman when available.
if command -v podman >/dev/null; then
  docker() {
    podman "$@"
  }
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

rm -rf dlls

# Build an image that has the dlls we care about.
docker build --iidfile=iid --pull context-dir
IMAGE="$(cat iid)"
# Extract them.
docker run --rm -v "$(pwd):/target:z" "$IMAGE" cp -r /root/dlls /target
rm iid

# Report an error if dll metadata changed.
echo "Checking dll metadata"
diff -u info.txt dlls/info.txt