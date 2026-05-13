FROM golang:1.26-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server/

FROM gcr.io/distroless/static-debian12
COPY --from=builder /server /server
USER 65534
EXPOSE 3000
ENTRYPOINT ["/server"]
