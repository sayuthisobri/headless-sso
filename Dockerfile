FROM --platform=linux/amd64 alpine:latest

RUN apk add --no-cache \
    bash \
    go

ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

WORKDIR /home/app
COPY ./entrypoint.sh entrypoint.sh
RUN chmod u+x ./entrypoint.sh

ENTRYPOINT ./entrypoint.sh
