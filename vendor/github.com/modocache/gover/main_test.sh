#!/bin/bash

PREFIX="test_main.sh:"
GOVER="$GOPATH/bin/gover"

echo "$PREFIX $GOVER"
$GOVER || exit 1
echo "$PREFIX rm gover.coverprofile"
rm gover.coverprofile || exit 1

echo "$PREFIX $GOVER gover/_fixtures/nested_cover_profiles"
$GOVER gover/_fixtures/nested_cover_profiles || exit 1
echo "$PREFIX rm gover.coverprofile"
rm gover.coverprofile || exit 1

echo "$PREFIX $GOVER gover/_fixtures/nested_cover_profiles out.coverprofile"
$GOVER gover/_fixtures/nested_cover_profiles out.coverprofile || exit 1
echo "$PREFIX rm out.coverprofile"
rm out.coverprofile || exit  1
