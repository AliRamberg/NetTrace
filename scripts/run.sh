#!/bin/bash
set -e

BPF_DIR="./pkg/bpf"
INTERFACE="eth0"
DEBUG_MODE=false

usage() {
    echo "Usage: $0 [-i INTERFACE|--interface INTERFACE] [-d|--debug]"
    echo "  -i, --interface INTERFACE Specify network interface (default: $INTERFACE)"
    echo "  -u --unload               Unload TC program from interface"
    echo "  -d, --debug               Enable debug mode"
    echo "  -h, --help                Display this help message"
    exit 1
}

unload_tc() {
    echo "Unloading TC program from $INTERFACE..."
    tc qdisc del dev $INTERFACE clsact
    echo "TC program unloaded from $INTERFACE."
}

trap unload_tc SIGINT

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
    -i | --interface)
        INTERFACE="$2"
        shift 2
        ;;
    -d | --debug)
        DEBUG_MODE=true
        shift
        ;;
    -u | --unload)
        unload_tc
        exit 0
        ;;
    *)
        usage
        ;;
    esac
done

[[ $(tc qdisc show | grep clsact | wc -l) -ne 0 ]] && unload_tc

echo "Loading TC program onto $INTERFACE..."

tc qdisc add dev $INTERFACE clsact

tc filter add dev $INTERFACE ingress bpf da obj $BPF_DIR/tc.o sec classifier
tc filter add dev $INTERFACE egress bpf da obj $BPF_DIR/tc.o sec classifier

# Additional debug actions
if $DEBUG_MODE; then
    echo "Debug mode is enabled."
    echo "Reading from trace_pipe. Press Ctrl+C to stop."
    sudo cat /sys/kernel/debug/tracing/trace_pipe
    unload_tc
fi
