FROM golang:1.21-alpine AS builder
WORKDIR /build
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /sal-kernel ./cmd/sal-kernel

FROM scratch
COPY --from=builder /sal-kernel /sal-kernel
EXPOSE 8443
ENTRYPOINT ["/sal-kernel"]
