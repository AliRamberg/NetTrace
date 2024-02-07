#ifndef COMMON_H
#define COMMON_H

#include "vmlinux.h"

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "bpf/bpf_core_read.h"

#define TC_ACT_OK 0

#define ETH_P_IP 0x0800
#define ETH_ALEN 6

#define TC_DEBUG 1

#ifdef TC_DEBUG

#define BPF_PRINTK(level, fmt, ...)                     \
    do                                                  \
    {                                                   \
        bpf_printk("[" #level "] " fmt, ##__VA_ARGS__); \
    } while (0)

#define BPF_PRINTK_DEBUG(fmt, ...) BPF_PRINTK(DEBUG, fmt, ##__VA_ARGS__)
#define BPF_PRINTK_INFO(fmt, ...) BPF_PRINTK(INFO, fmt, ##__VA_ARGS__)
#define BPF_PRINTK_WARN(fmt, ...) BPF_PRINTK(WARN, fmt, ##__VA_ARGS__)
#define BPF_PRINTK_ERROR(fmt, ...) BPF_PRINTK(ERROR, fmt, ##__VA_ARGS__)

#else

#define BPF_PRINTK_DEBUG(fmt, ...) \
    do                             \
    {                              \
    } while (0)
#define BPF_PRINTK_INFO(fmt, ...) \
    do                            \
    {                             \
    } while (0)
#define BPF_PRINTK_WARN(fmt, ...) \
    do                            \
    {                             \
    } while (0)
#define BPF_PRINTK_ERROR(fmt, ...) \
    do                             \
    {                              \
    } while (0)

#endif

#endif // COMMON_H