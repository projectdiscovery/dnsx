#!/bin/bash

echo "::group::Build dnsx"
rm integration-test dnsx 2>/dev/null
cd ../cmd/dnsx
go build
mv dnsx ../../integration_tests/dnsx
echo "::endgroup::"
echo "::group::Build nuclei integration-test"
cd ../integration-test
go build
mv integration-test ../../integration_tests/integration-test 
cd ../../integration_tests
echo "::endgroup::"
./integration-test
if [ $? -eq 0 ]
then
  exit 0
else
  exit 1
fi
