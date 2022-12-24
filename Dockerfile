FROM golang:1.19-alpine as builder

# Setup
RUN mkdir -p /go/src/github.com/turnly/oauth-middleware
WORKDIR /go/src/github.com/turnly/oauth-middleware

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/turnly/oauth-middleware/
RUN CGO_ENABLED=0 GOOS=linux GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/turnly/oauth-middleware/cmd

# Copy into scratch container
FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /traefik-forward-auth ./
ENTRYPOINT ["./traefik-forward-auth"]
