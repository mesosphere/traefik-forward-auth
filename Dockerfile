FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git

COPY . /src
RUN \
  cd /src && \
  CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o /traefik-forward-auth ./cmd

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth /
ENTRYPOINT ["/traefik-forward-auth"]
