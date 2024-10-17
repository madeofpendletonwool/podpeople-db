# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app
RUN mkdir -p /app/podpeople-data

RUN apk add build-base

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o main .

# Runtime stage
FROM alpine:latest  

RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the pre-built binary file from the previous stage
COPY --from=builder /app/main .
COPY --from=builder /app/startup.sh .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

# Make sure the startup script is executable
RUN chmod +x /root/startup.sh

# Expose port 8080
EXPOSE 8080

# Run the startup script
CMD ["/root/startup.sh"]