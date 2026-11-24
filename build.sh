#!/usr/bin/env bash
# Compile RED-O from source on the target Linux host.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if ! command -v go >/dev/null 2>&1; then
  echo "Go 1.23+ is required. Install Go and retry ./build.sh" >&2
  exit 1
fi
mkdir -p bin
echo "Building RED-O for $(go env GOOS)/$(go env GOARCH) with $(go version)"
go build -trimpath -o bin/red-o ./cmd/red-o
./bin/red-o version
echo "Build completed: ./bin/red-o"
