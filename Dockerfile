FROM golang:1.15-alpine3.12 AS build-env

RUN apk add --no-cache --upgrade git openssh-client ca-certificates
WORKDIR /go/src/app

# Install
RUN go get -u -v github.com/projectdiscovery/dnsx/cmd/dnsx

ENTRYPOINT ["dnsx"]
