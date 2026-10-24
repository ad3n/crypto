#!/bin/sh
set -eu
repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
consumer_dir=$(mktemp -d "${TMPDIR:-/tmp}/crypto-consumer.XXXXXX")
trap 'rm -rf "$consumer_dir"' EXIT HUP INT TERM
cp "$repo_dir/testdata/consumer_test.go" "$consumer_dir/consumer_test.go"
cd "$consumer_dir"
export GOWORK=off
export GOFLAGS=
go mod init example.com/crypto-consumer
go get "github.com/ad3n/crypto/v2@${1:-master}"
go mod tidy
go list -m all
go test -race -gcflags=all=-d=checkptr=2 -v ./...
