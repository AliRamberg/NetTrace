FROM golang:1.21.6-alpine3.19 AS builder

RUN apk update && \
  apk add --no-cache \
  clang llvm \
  libbpf-dev \
  make git

COPY . /src
WORKDIR /src

RUN make release

FROM alpine:3.19.1
COPY --from=builder /src/netrace /usr/local/bin/netrace
ENTRYPOINT [ "netrace" ]