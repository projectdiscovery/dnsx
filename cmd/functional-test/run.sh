#!/bin/bash

echo 'Building functional-test binary'
go build

echo 'Building DNSX binary from current branch'
go build -o dnsx_dev ../dnsx

echo 'Installing latest release of DNSX'
GO111MODULE=on go build -v github.com/projectdiscovery/dnsx/cmd/dnsx

echo 'Starting DNSX functional test'
./functional-test -main ./dnsx -dev ./dnsx_dev -testcases testcases.txt
