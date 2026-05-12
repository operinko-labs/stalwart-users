# Placeholder Dockerfile for Stalwart User Management API
# To be implemented in task 2

FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY . .
RUN go build -o server ./cmd/server

FROM alpine:latest

RUN apk --no-cache add ca-certificates
WORKDIR /root/

COPY --from=builder /app/server .

EXPOSE 3000
CMD ["./server"]
