# Default network interface
INTERFACE ?= eth0
WDIR := ./pkg/bpf

# eBPF program source and output names
EBPF_SRC := $(WDIR)/tc.c
EBPF_OUT := $(WDIR)/tc.o


# Compilation flags
CFLAGS := -O2 -target bpf -g -c -I/usr/include/${shell uname -m}-linux-gnu
DEBUG_CFLAGS := $(CFLAGS) -DTC_DEBUG

.PHONY: build build-debug
release:
	go generate ./...
	CGO_ENABLED=0 go build -o netrace main.go

build-debug: $(EBPF_OUT)
$(EBPF_OUT): $(EBPF_SRC)
	clang $(DEBUG_CFLAGS) -o $@ $(EBPF_SRC)


local-run-dev: build-debug
	sudo ./scripts/run.sh -i $(INTERFACE) -d

local-run: build
	sudo ./scripts/run.sh -i $(INTERFACE)

clean:
	rm -f $(EBPF_OUT)
	rm -f bpf/tc_bpf.o
	rm -f bpf/tc_bpf.go
	sudo ./scripts/run.sh --unload

run:
	go env -w CGO_ENABLED=0
	go generate ./...
	sudo -E go run main.go -i $(INTERFACE)

.PHONY: local-run-dev local-run clean
