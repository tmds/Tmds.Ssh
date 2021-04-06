#!/bin/bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR"

rm -rf dlls

# Build an image that has the dlls we care about.
podman build --iidfile=iid --pull-always context-dir
IMAGE="$(cat iid)"
# Extract them.
podman run --rm -v .:/target:z "$IMAGE" cp -r /root/dlls /target
rm iid

# Report an error if dll metadata changed.
echo "Checking dll metadata"
diff -u info.txt dlls/info.txt