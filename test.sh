#!/bin/bash
set -o errexit
cd $(dirname $0)
ls $GOPATH/src/github.com/cloudflare/cfssl

PACKAGES=$(go list ./... | grep -v /vendor/)

go vet $PACKAGES
if ! which fgt > /dev/null ; then
  echo "Please install fgt from https://github.com/GeertJohan/fgt."
  exit 1
fi

if ! which golint > /dev/null ; then
  echo "Please install golint from github.com/golang/lint/golint."
  exit 1
fi

for package in $PACKAGES
do
        fgt golint ${package##github.com/cloudflare/cfssl/}/*.go
done

# Build and install cfssl executable in PATH
go install github.com/cloudflare/cfssl/cmd/cfssl

go test $BUILD_FLAGS $PACKAGES
go list -f '{{if len .TestGoFiles}}"go test -coverprofile={{.Dir}}/.coverprofile {{.ImportPath}}"{{end}}' $PACKAGES | xargs -I "sh -c {}"
gover . coverprofile.txt
