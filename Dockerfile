# BUILD
FROM golang:1.14-alpine as build

ENV GO111MODULE=on

WORKDIR /build

COPY go.mod go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/service cmd/peer/main.go

# RUN
FROM alpine
WORKDIR /app

COPY --from=build /build/bin/* /app/
CMD ["/app/service"]
