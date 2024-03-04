#!/bin/bash

PACKAGE="$1"
echo "Installing $PACKAGE"
# sudo -u ab -D~ bash -c "aur-install $PACKAGE"
aur-install "$PACKAGE"
