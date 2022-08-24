#!/bin/bash
set -e

# Build and install all binaries in PATH
export GOBIN="${HOME}/bin"
export PATH="${PATH}:${GOBIN}"
make install

# Run go tests
echo "" > coverage.txt
for package in $(go list ./...); do
    if echo "$package" | grep -q "/scan/crypto"; then
        echo "skipped $package"
        continue
    fi

    # only run the race detector on x86_64
    if [ "$(uname -m)" = "x86_64" ]; then
        go test -mod=vendor -tags "$BUILD_TAGS" -race -coverprofile=profile.out -covermode=atomic $package
    else
        go test -mod=vendor -tags "$BUILD_TAGS" -coverprofile=profile.out $package
    fi

    if [ -f profile.out ]; then
        cat profile.out >> coverage.txt
        rm profile.out
    fi
done

