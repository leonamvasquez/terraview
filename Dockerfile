# ============================================================================
# terraview — Terraform Security & AI Review Tool
# Multi-stage production build
# ============================================================================

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM golang:1.26.2-alpine@sha256:c2a1f7b2095d046ae14b286b18413a05bb82c9bca9b25fe7ff5efef0f0826166 AS builder

ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w \
      -X main.version=${VERSION} \
      -X main.commit=${COMMIT} \
      -X main.buildDate=${BUILD_DATE}" \
    -o /build/terraview .

# ---------------------------------------------------------------------------
# Stage 2: Runtime (distroless-style minimal image)
# ---------------------------------------------------------------------------
FROM alpine:3.23@sha256:25109184c71bdad752c8312a8623239686a9a2071e8825f20acb8f2198c3f659

ARG VERSION=dev
ARG BUILD_DATE=unknown

# OCI standard labels
LABEL org.opencontainers.image.title="terraview" \
      org.opencontainers.image.description="Terraform Security & AI Review Tool — Static analysis + multi-provider AI contextual review" \
      org.opencontainers.image.url="https://github.com/leonamvasquez/terraview" \
      org.opencontainers.image.source="https://github.com/leonamvasquez/terraview" \
      org.opencontainers.image.documentation="https://github.com/leonamvasquez/terraview#readme" \
      org.opencontainers.image.vendor="leonamvasquez" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.created="${BUILD_DATE}"

RUN apk --no-cache upgrade \
    && apk add --no-cache ca-certificates tzdata \
    && addgroup -g 1000 terraview \
    && adduser -u 1000 -G terraview -s /bin/sh -D terraview \
    && mkdir -p /home/terraview/.terraview/prompts /workspace \
    && chown -R terraview:terraview /home/terraview /workspace

COPY --from=builder /build/terraview /usr/local/bin/terraview
COPY --chown=terraview:terraview prompts/ /home/terraview/.terraview/prompts/

USER terraview
WORKDIR /workspace

ENTRYPOINT ["terraview"]
CMD ["--help"]
