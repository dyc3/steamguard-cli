#!/bin/bash

PACKAGE="$1"
echo "Installing $PACKAGE"
sudo -u ab -D~ bash -c "yay -Syu --removemake --needed --noprogressbar --noconfirm $PACKAGE"
