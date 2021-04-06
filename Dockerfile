FROM golang:1.16.0-alpine3.12 AS build-env
RUN GO111MODULE=on go get -v github.com/projectdiscovery/dnsx/cmd/dnsx

FROM alpine:latest
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/dnsx /usr/local/bin/dnsx
ENTRYPOINT ["dnsx"]
