# Stage 1: Build (cross-compile via Go, runs natively on the build host)
FROM --platform=$BUILDPLATFORM golang:1.23-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} go build \
    -ldflags="-s -w" \
    -o /out/bouncer \
    ./cmd/bouncer

# Pre-create /data owned by uid 65532 (distroless 'nonroot').
# Docker copies this directory (with its perms) into a fresh named volume on first mount.
RUN mkdir -p /out/data && chown 65532:65532 /out/data

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/bouncer /bouncer
COPY --from=builder --chown=nonroot:nonroot /out/data /data

USER nonroot

EXPOSE 8080

VOLUME ["/data"]

ENTRYPOINT ["/bouncer"]
