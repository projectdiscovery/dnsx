FROM golang:1.16.7-alpine3.14 AS build-env
RUN go get -v github.com/projectdiscovery/dnsx/cmd/dnsx

FROM alpine:3.14
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/dnsx /usr/local/bin/dnsx
ENTRYPOINT ["dnsx"]
