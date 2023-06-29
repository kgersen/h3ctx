# syntax=docker/dockerfile:1
# Build the application from source
FROM golang:latest AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -o h3ctx

FROM alpine:latest  
RUN apk --no-cache add ca-certificates

WORKDIR /

COPY --from=builder /app/h3ctx ./

ENTRYPOINT ["/h3ctx"]
