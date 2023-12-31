################################################################################
# Build
################################################################################
FROM golang:1.21-alpine3.18 as builder

ARG BUILD_TAGS

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

RUN make static build_tags="${BUILD_TAGS}"

################################################################################
# Final
################################################################################
FROM alpine:3.18

RUN apk update && apk add ca-certificates

COPY --from=builder /app/build/go-lanscan /scan

RUN mkdir -p /reports

ENTRYPOINT [ "/scan", "--out-file", "/reports/scan-report.json" ]
