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

# Stage 2: Runtime
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/bouncer /bouncer

USER nonroot

EXPOSE 8080

VOLUME ["/data"]

ENTRYPOINT ["/bouncer"]
