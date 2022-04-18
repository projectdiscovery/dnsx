FROM golang:1.17.8-alpine3.14 AS build-env
RUN apk add --no-cache build-base
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest

FROM alpine:3.15.0
RUN apk add --no-cache bind-tools ca-certificates
COPY --from=build-env /go/bin/dnsx /usr/local/bin/dnsx
ENTRYPOINT ["dnsx"]
