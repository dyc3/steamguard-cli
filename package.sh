#!/bin/bash

VERSION=$(build/steamguard --help | head -n 1 | cut -d v -f 2)"-0"
TEMP_PKG_PATH="/tmp/steamguard-cli_$VERSION"
echo Building Debian package for v$VERSION...

mkdir -p $TEMP_PKG_PATH/usr/local/bin
mkdir -p $TEMP_PKG_PATH/etc/bash_completion.d
mkdir -p $TEMP_PKG_PATH/DEBIAN

cp build/* $TEMP_PKG_PATH/usr/local/bin
cp bash-tab-completion $TEMP_PKG_PATH/etc/bash_completion.d/steamguard

cat <<EOT >> $TEMP_PKG_PATH/DEBIAN/control
Package: steamguard-cli
Version: $VERSION
Section: base
Priority: optional
Architecture: all
Maintainer: Carson McManus <dyc3@users.noreply.github.com>
Description: steamguard-cli
 A command line utility to generate Steam Guard codes
 (AKA 2 factor authentication codes).
EOT

dpkg-deb --build $TEMP_PKG_PATH steamguard-cli_$VERSION.deb

rm -rf $TEMP_PKG_PATH
