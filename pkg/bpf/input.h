#ifndef INPUT_H
#define INPUT_H

#include "common.h"

#define MAX_PACKET_SIZE 8192

struct event
{
    __u64 timestamp;
    __u8 data[MAX_PACKET_SIZE];
};

struct __attribute__((packed)) query
{
    struct ethhdr eth;      // 14 bytes
    struct iphdr ip;        // 20 bytes
    union {                 // 20 bytes (max size of TCP and UDP headers)
        struct udphdr udp;
        struct tcphdr tcp;
    };
};                          // 54 bytes total

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct query));
    __uint(max_entries, 5);
} queries SEC(".maps");

#endif