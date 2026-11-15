FROM golang:1.23-alpine AS build

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .
RUN go mod tidy
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/api ./cmd/api

FROM alpine:3.21

RUN apk add --no-cache ca-certificates wget \
    && adduser -D -H -u 10001 appuser

WORKDIR /app
COPY --from=build /out/api /app/api

USER appuser
EXPOSE 8080

ENTRYPOINT ["/app/api"]
