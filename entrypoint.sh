#!/usr/bin/env bash

pushd src
go build -ldflags="-s -w" -o ./build/headless-sso
