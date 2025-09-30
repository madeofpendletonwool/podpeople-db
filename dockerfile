# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache gcc musl-dev

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -o podpeopledb ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata sqlite

WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/podpeopledb .
# Copy templates and static files
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Create data directory
RUN mkdir -p /app/podpeople-data

# Expose port
EXPOSE 8085

# Run the application
CMD ["/app/podpeopledb"]
