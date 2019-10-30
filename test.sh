#!/bin/bash
set -o errexit

ARCH="$(uname -m)"
export WORDDIR=$(pwd)
export PATH="$PATH:$WORDDIR/bin"

PACKAGES=""
if [ "$#" != 0 ]; then
    for pkg in "$@"; do
        PACKAGES="$PACKAGES $pkg"
    done
else
    PACKAGES=$(go list ./... | grep -v /scan/crypto)
fi

# Build and install cfssl executable in PATH
go build -tags "$BUILD_TAGS" -o "$WORDDIR/bin/cfssl" "$WORDDIR/cmd/cfssl"

if [ $ARCH = 'x86_64'  ]; then
    go test -race -tags "$BUILD_TAGS" --coverprofile=coverprofile.txt $PACKAGES
else
    go test -tags "$BUILD_TAGS" --coverprofile=coverprofile.txt $PACKAGES
fi

if ! command -v golint > /dev/null ; then
    go get golang.org/x/lint/golint
fi

golint -set_exit_status=1 $PACKAGES
