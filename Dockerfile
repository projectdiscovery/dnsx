FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="A fast and multi-purpose DNS toolkit designed for running DNS queries"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="dnsx"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/dnsx"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/dnsx /usr/local/bin/

ENTRYPOINT ["dnsx"]
