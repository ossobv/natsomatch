#!/bin/sh
set -e
here=$(cd "$(dirname "$0")"; pwd)
sudo docker build --build-arg="GIT_VERSION=$(git describe --always --dirty=-modified)" -t build-nats2jetstream "$here"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sudo docker image save build-nats2jetstream | tar -C "$tmp" -x
find "$tmp" -type f -name layer.tar -print0 | xargs -0 tar -xvf
ls -l ./nats2jetstream
