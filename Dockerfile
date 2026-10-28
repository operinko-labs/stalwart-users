FROM docker.io/library/golang:1.27-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server/
RUN CGO_ENABLED=0 GOOS=linux go build -o /migrate-directory ./cmd/migrate-directory/

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
COPY --from=builder /migrate-directory /migrate-directory
USER 65534
EXPOSE 3000
ENTRYPOINT ["/server"]
