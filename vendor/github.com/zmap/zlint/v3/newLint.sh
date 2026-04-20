#!/usr/bin/env bash

function usage() {
  echo "./newLint.sh [-h|--help] -r|--req <REQUIREMENT> -f|--file <FILENAME> -s|--struct <STRUCTNAME>"
  echo ""
  echo "Options:"
  echo "  -h|--help   Prints this help text."
  echo "  -r|--req    The name of the requirements body governing this lint. Valid options are $(valid_requirement_names)."
  echo "  -f|--file   The target filename for the given lint (no file extension is required)."
  echo "  -s|--struct The name of the Golang struct to create."
  echo ""
  echo "Example:"
  echo "  $ ./newLint.sh --req rfc --file crl_must_be_good --struct CrlMustBeGood "
  echo "    Created lint file /home/chris/projects/zlint/v3/lints/rfc/lint_crl_must_be_good.go with struct name CrlMustBeGood"
  echo "    Created test file /home/chris/projects/zlint/v3/lints/rfc/lint_crl_must_be_good_test.go"
}

function git_root() {
    git rev-parse --show-toplevel
}

# Searches within the v3/lints directory for a subdirectory matching
# the name of the governing requirements body provided by the -r|--req flag.
#
# Exits with error code 1 if no such directory is found
function requirement_dir_exists() {
    exists=$(find "$(git_root)/v3/lints/" -maxdepth 1 -type d -not -name lints -name "${1}")
    if [ -z "${exists}" ]; then
      echo "Unknown requirements body (${1}). Valid options are $(valid_requirement_names)."
      usage
      exit 1
    fi
}

# Echoes out a comma separated list of directories within v3/lints
function valid_requirement_names() {
    names=$(find "$(git_root)/v3/lints/" -type d -not -name "lints" -exec basename {} \;)
    echo -n "${names}" | tr '\n' ', '
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -r | --req)
      requirement_dir_exists "${2}"
      REQUIREMENT="${2}"
      shift 2
      ;;
    -f | --file)
      LINTNAME="${2}"
      FILENAME="lint_${LINTNAME}.go"
      TEST_FILENAME="lint_${LINTNAME}_test.go"
      shift 2
      ;;
    -s | --struct)
      STRUCTNAME="$2"
      shift 2
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [ -z "${REQUIREMENT}" ]; then
  echo "The -r|--req flag is required. Valid options are $(valid_requirement_names)"
  usage
  exit 1
fi

if [ -z "${LINTNAME}" ]; then
  echo "The -f|--file flag is required."
  usage
  exit 1
fi

if [ -z "${STRUCTNAME}" ]; then
  echo "The -s|--strut flag is required."
  usage
  exit 1
fi

PATHNAME="$(git_root)/v3/lints/${REQUIREMENT}/${FILENAME}"
TEST_PATHNAME="$(git_root)/v3/lints/${REQUIREMENT}/${TEST_FILENAME}"

sed -e "s/PACKAGE/${REQUIREMENT}/" \
    -e "s/PASCAL_CASE_SUBST/${STRUCTNAME^}/g" \
    -e "s/SUBST/${STRUCTNAME}/g" \
    -e "s/SUBTEST/${LINTNAME}/g" "$(git_root)/v3/template" > "${PATHNAME}"

sed -e "s/PACKAGE/${REQUIREMENT}/" \
    -e "s/PASCAL_CASE_SUBST/${STRUCTNAME^}/g" \
    -e "s/SUBST/${STRUCTNAME}/g" \
    -e "s/SUBTEST/${LINTNAME}/g" "$(git_root)/v3/test_template" > "${TEST_PATHNAME}"

echo "Created lint file ${PATHNAME} with struct name ${STRUCTNAME}"
echo "Created test file ${TEST_PATHNAME}"
