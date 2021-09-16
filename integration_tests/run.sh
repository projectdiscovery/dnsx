#!/bin/bash

rm integration-test dnsx 2>/dev/null
cd ../cmd/dnsx
go build
mv dnsx ../../integration_tests/dnsx
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test 
cd ../../integration_tests
./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
