FROM golang:1.14-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/mesosphere/traefik-forward-auth
WORKDIR /go/src/github.com/mesosphere/traefik-forward-auth

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/mesosphere/traefik-forward-auth/
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/mesosphere/traefik-forward-auth/cmd

# Copy into alpine container
FROM alpine
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
