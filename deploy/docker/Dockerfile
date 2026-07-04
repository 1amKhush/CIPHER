# Standard multi-stage build for Go applications
FROM golang:1.21-alpine AS builder

# Set the working directory outside $GOPATH to enable the support for modules.
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source from the current directory to the Working Directory inside the container
COPY . .

# Build the Go app (adjust path if needed to point to your specific main.go)
RUN CGO_ENABLED=0 GOOS=linux go build -o /app/cipher-app ./cmd/...

# Start a new stage from scratch
FROM alpine:latest
WORKDIR /app

# Copy the Pre-built binary file from the previous stage
COPY --from=builder /app/cipher-app .

# Command to run the executable
ENTRYPOINT ["/app/cipher-app"]
