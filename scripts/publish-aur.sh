#!/bin/bash
set -e

DRY_RUN=true

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  key="$1"

  case $key in
    --execute)
      DRY_RUN=false
      shift # past argument
      ;;
    *)    # unknown option
      POSITIONAL+=("$1") # save it in an array for later
      shift # past argument
      ;;
  esac
done

# prerequisites
if ! command -v makepkg &> /dev/null; then
  echo "Error: makepkg is not installed"
  exit 1
fi
if ! command -v git &> /dev/null; then
  echo "Error: git is not installed"
  exit 2
fi


# get version info
BIN_PATH="target/release/steamguard-cli"
RAW_VERSION="$("$BIN_PATH" --version | cut -d " " -f 2)"
TAGGED_VERSION="$(git tag | grep "^v" | tail -n 1 | tr -d v)"
if [[ "v$RAW_VERSION" != "v$TAGGED_VERSION" ]]; then
  echo "Version mismatch: $RAW_VERSION != $TAGGED_VERSION"
  exit 10
fi
VERSION="v$RAW_VERSION"

# update PKGBUILD for AUR
if [[ -d "aur" ]]; then
	rm -rf aur
fi
git clone ssh://aur@aur.archlinux.org/steamguard-cli-git.git aur
cp PKGBUILD aur/PKGBUILD
cd aur
git commit -m "release $VERSION" PKGBUILD
if [[ $DRY_RUN == false ]]; then
	git push
	rm -rf aur
fi
cd ..