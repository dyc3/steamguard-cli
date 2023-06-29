#!/bin/bash

set -e

DRY_RUN=true
SKIP_CRATE_PUBLISH=false

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    --execute)
      DRY_RUN=false
      shift # past argument
      ;;
    --bump)
      BUMP="$2"
      shift # past argument
      shift # past value
      ;;
    --skip-publish)
      SKIP_CRATE_PUBLISH=true
      shift # past argument
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done

current_branch=$(git rev-parse --abbrev-ref HEAD)

if [[ "$current_branch" != "master" ]]; then
  echo "You must be on the master branch to run this script"
  exit 1
fi

git pull

echo """
This will do everything needed to release a new version:
- bump the version number
- create a git tag
- build all artifacts
- publish crates on crates.io
- upload artifacts to a new release on github
"""
if [ "$DRY_RUN" = true ]; then
	echo "This is a dry run, nothing will be done. Artifacts will be built, but not published. Use --execute to do it for real."
else
	echo "This is not a dry run. This is the real deal!"
fi
echo "Press any key to continue..."
read -n 1 -s -r

params=()
if [[ $DRY_RUN == false ]]; then
	params+=(--execute)
fi
if [[ $BUMP != "" ]]; then
	params+=(--bump "$BUMP")
	params+=(--bump-dependencies "$BUMP")
fi
if [[ $SKIP_CRATE_PUBLISH == true ]]; then
	params+=(--no-publish)
fi
cargo smart-release --update-crates-index --no-changelog --no-publish "${params[@]}"

#echo "Verify that the publish succeeded, and Press any key to continue..."
# read -n 1 -s -r

if ! which cross; then
	echo "cross not found, installing..."
	cargo install cross
fi

BUILD_TARGET="x86_64-unknown-linux-musl"
BUILD_TARGET2="x86_64-pc-windows-gnu"
cross build --release "--target=$BUILD_TARGET"
cross build --release "--target=$BUILD_TARGET2"

./scripts/package-deb.sh

BIN_PATH="target/$BUILD_TARGET/release/steamguard"
BIN_PATH2="target/$BUILD_TARGET2/release/steamguard.exe"
RAW_VERSION="$("$BIN_PATH" --version | cut -d " " -f 2)"
TAGGED_VERSION="$(git tag | grep "^v" | tail -n 1 | tr -d v)"
if [[ "v$RAW_VERSION" != "v$TAGGED_VERSION" ]]; then
  echo "Version mismatch: $RAW_VERSION != $TAGGED_VERSION"
fi
VERSION="v$RAW_VERSION"

if [[ $DRY_RUN == false ]]; then
  if [[ $(gh release list | grep -i "Draft" | grep -i "$VERSION" && echo "true" || echo "false") == "true" ]]; then
    gh release delete --yes "$VERSION"
  fi
	gh release create "$VERSION" --title "$VERSION" --draft "$BIN_PATH" "$BIN_PATH2" "./steamguard-cli_$RAW_VERSION-0.deb"
fi

echo "It's now safe to run cargo publish for the affected crates."
