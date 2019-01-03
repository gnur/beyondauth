FROM golang:1.11-alpine as builder
WORKDIR /go/src/github.com/gnur/beyondauth/
RUN apk add --no-cache --virtual .build-deps \ 
    bash \ 
    gcc \ 
    musl-dev \ 
    openssl 
COPY vendor vendor
COPY jwt jwt
COPY *.go ./
RUN go build -o beyondauth *.go

FROM alpine:latest
RUN apk update && apk add ca-certificates
COPY --from=builder /go/src/github.com/gnur/beyondauth/beyondauth /
EXPOSE 8080
CMD ["./beyondauth"]
