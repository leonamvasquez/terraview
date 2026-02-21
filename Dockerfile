FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev)" \
    -o /build/terraview .

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

COPY --from=builder /build/terraview /usr/local/bin/terraview
COPY --from=builder /build/prompts /root/.terraview/prompts

ENTRYPOINT ["terraview"]
