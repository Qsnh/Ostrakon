#!/usr/bin/env bash
# Linux end-to-end test, run from the host: builds the linux binaries into
# test/e2e/bin/, builds the test image and runs run.sh in a privileged
# container, against real nftables and a fake Jev. Needs Go and Docker.
# Exits with the container's status; on success the last line is E2E PASS.
#
#   bash test/e2e/e2e.sh
set -euo pipefail

e2e_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$e2e_dir/../.." && pwd)
image=ostrakon-e2e

cd "$root"
arch=$(go env GOARCH)
echo "==> building linux/$arch binaries into test/e2e/bin/"
mkdir -p "$e2e_dir/bin"
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$e2e_dir/bin/ostrakon" ./cmd/ostrakon
GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -o "$e2e_dir/bin/fakejev" ./test/e2e/fakejev

echo "==> building image $image"
docker build -t "$image" "$e2e_dir"

echo "==> running the suite in a privileged container (takes a few minutes)"
exec docker run --rm --privileged "$image"
