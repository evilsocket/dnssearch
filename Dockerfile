FROM golang:1.8 as build-stage
WORKDIR /go/src/github.com/evilsocket/dnssearch
COPY main.go .
RUN go get && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dnssearch .

FROM alpine:latest
WORKDIR /app
COPY --from=build-stage /go/src/github.com/evilsocket/dnssearch/dnssearch /app
COPY names.txt /app
ENTRYPOINT ["/app/dnssearch"]
