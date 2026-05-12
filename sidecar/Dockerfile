# Stage 1: Build
FROM golang:1.23-alpine AS builder

WORKDIR /src

# Copy module files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with optimizations for distribution
RUN CGO_ENABLED=0 GOOS=linux go build \
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
