#!/bin/bash

# Performs a test install of the package from the AUR. If the package fails to install, there should be a non-zero exit code.
# Intended for use with CI.

set -e

cd scripts/docker/arch/
tar -cvf arch-docker.tar.gz .
docker image build -t steamguard-cli-archlinux-builder - < arch-docker.tar.gz
rm arch-docker.tar.gz

docker run -it --rm steamguard-cli-archlinux-builder /bin/bash -c "./install.sh steamguard-cli-git && steamguard-cli --version"

docker image rm steamguard-cli-archlinux-builder:latest
