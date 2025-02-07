#!/bin/sh
set -e
here=$(cd "$(dirname "$0")"; pwd)
sudo docker build --build-arg="GIT_VERSION=$(git describe --always --dirty=-modified)" -t build-natsomatch "$here"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sudo docker image save build-natsomatch | tar -C "$tmp" -x

if test -f "$tmp/repositories"; then
    layertar=$(jq -r '.["build-natsomatch"].latest' <"$tmp/repositories")
    if test -n "$layertar"; then
        layertar=$tmp/blobs/sha256/$layertar
    fi
else
    layertar=$(find "$tmp" -type f -name layer.tar)
fi
if test -z "$layertar"; then
    echo "$0: could not parse docker layout to extract output" >&2
fi
tar -xvf "$layertar"
ls -l ./natsomatch
