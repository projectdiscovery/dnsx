#!/bin/bash

# reading os type from arguments
CURRENT_OS=$1

if [ "${CURRENT_OS}" == "windows-latest" ];then
    extension=.exe
fi

echo "::group::Building functional-test binary"
go build -o functional-test$extension
echo "::endgroup::"

echo "::group::Building dnsx binary from current branch"
go build -o dnsx_dev$extension ../dnsx
echo "::endgroup::"

echo "::group::Building latest release of dnsx"
go build -o dnsx$extension -v github.com/projectdiscovery/dnsx/cmd/dnsx
echo "::endgroup::"

echo 'Starting dnsx functional test'
./functional-test$extension -main ./dnsx$extension -dev ./dnsx_dev$extension -testcases testcases.txt
