FROM golang:1.16.2-alpine3.12 AS build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx

FROM alpine:3.13.2
COPY --from=build-env /go/bin/dnsx /usr/local/bin/dnsx
ENTRYPOINT ["dnsx"]
