FROM golang:alpine AS builder

RUN mkdir /app
WORKDIR /app
COPY *.go go.mod go.sum /app/
RUN go mod download && go build -o broker

FROM alpine

RUN mkdir /app
WORKDIR /app
COPY --from=builder /app/broker broker
ENTRYPOINT ["/app/broker"]