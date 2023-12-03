################################################################################
# Build
################################################################################
FROM golang:1.21-alpine3.18 as builder

RUN apk update && apk add \
  make \
  linux-headers \
  musl-dev \
  gcc \
  libpcap-dev

WORKDIR /app

COPY internal internal
COPY pkg pkg
COPY go.mod go.sum main.go Makefile ./

RUN make static

################################################################################
# Final
################################################################################
FROM alpine:3.18

COPY --from=builder /app/build/go-lanscan /scan

ENTRYPOINT [ "/scan" ]
