# Multi-stage production build for Author Identity Relay
FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build stripped, statically-linked pure-Go relay binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /relay ./cmd/relay

# Production runtime container
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata && mkdir -p /app/data

WORKDIR /app

COPY --from=builder /relay /app/relay
COPY web /app/web

ENV PORT=8080
ENV STATIC_DIR=/app/web
ENV DB_PATH=/app/data/author.db

EXPOSE 8080

VOLUME ["/app/data"]

CMD ["/app/relay"]
