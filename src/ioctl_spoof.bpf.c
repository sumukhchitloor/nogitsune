// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SIOCGIFHWADDR 0x8927
#define IFNAMSIZ 16

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

// Target interface to spoof. Must be const VOLATILE, not plain const - a
// plain const global can be constant-folded by the compiler at -O2, which
// would silently ignore any userspace override written into rodata before
// load.
const volatile char target_iface[IFNAMSIZ] = "eth0";

// Fake MAC address (Dell OUI: a4:5e:60:xx:xx:xx)
const volatile unsigned char fake_mac[6] = {0xa4, 0x5e, 0x60, 0x12, 0x34, 0x56};

// Ring buffer for logging events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Event structure for logging
struct mac_spoof_event {
    u32 pid;
    char comm[16];
    char iface[IFNAMSIZ];
    unsigned char original_mac[6];
    unsigned char spoofed_mac[6];
    bool success;
};

// Map to track ioctl calls we need to modify
// Key: pid_tgid, Value: pointer to ifreq structure
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, unsigned long);
} pending_ioctls SEC(".maps");

SEC("tp/syscalls/sys_enter_ioctl")
int ioctl_entry(struct trace_event_raw_sys_enter *ctx)
{
    // args[0]=fd, args[1]=cmd, args[2]=arg
    unsigned int cmd = (unsigned int)ctx->args[1];
    unsigned long arg = (unsigned long)ctx->args[2];
    
    log_bpf("ioctl called: cmd=0x%x SIOCGIFHWADDR=0x%x", cmd, SIOCGIFHWADDR);
    
    if (cmd != SIOCGIFHWADDR) {
        return 0;
    }
    
    log_bpf("SIOCGIFHWADDR detected! arg=0x%lx", arg);
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_ioctls, &pid_tgid, &arg, BPF_ANY);
    
    return 0;
}

SEC("tp/syscalls/sys_exit_ioctl")
int ioctl_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;
    
    // Check if this was a SIOCGIFHWADDR call we're tracking
    unsigned long *arg_ptr = bpf_map_lookup_elem(&pending_ioctls, &pid_tgid);
    if (!arg_ptr) {
        return 0;
    }
    
    unsigned long arg = *arg_ptr;
    bpf_map_delete_elem(&pending_ioctls, &pid_tgid);
    
    // Only modify if ioctl succeeded
    if (ret < 0) {
        log_bpf("ioctl failed with ret=%d, skipping", ret);
        return 0;
    }
    
    // The ifreq structure layout:
    // struct ifreq {
    //     char ifr_name[16];          // offset 0
    //     union {
    //         struct sockaddr ifr_hwaddr;  // offset 16
    //             // sa_family: 2 bytes (offset 16)
    //             // sa_data[14]: MAC at bytes [0-5] (offset 18)
    //     };
    // };
    
    // Read interface name to verify it's our target
    char iface_name[IFNAMSIZ] = {};
    if (bpf_probe_read_user(iface_name, IFNAMSIZ, (void *)arg) < 0) {
        log_bpf("Failed to read interface name");
        return 0;
    }
    
    log_bpf("Interface: %s", iface_name);
    
    // Check if this is the target interface (eth0)
    bool is_target = true;
    for (int i = 0; i < IFNAMSIZ && target_iface[i] != '\0'; i++) {
        if (iface_name[i] != target_iface[i]) {
            is_target = false;
            break;
        }
    }
    
    if (!is_target) {
        log_bpf("Not target interface, skipping");
        return 0;
    }
    
    log_bpf("Target interface matched! Spoofing MAC...");
    
    // Read original MAC address for logging
    unsigned char original_mac[6] = {};
    unsigned long mac_offset = arg + 18; // ifr_name(16) + sa_family(2)
    bpf_probe_read_user(original_mac, 6, (void *)mac_offset);
    
    log_bpf("Original MAC: %02x:%02x:%02x:%02x:%02x:%02x",
               original_mac[0], original_mac[1], original_mac[2],
               original_mac[3], original_mac[4], original_mac[5]);
    
    // Write fake MAC address
    if (bpf_probe_write_user((void *)mac_offset, (void *)fake_mac, 6) < 0) {
        log_bpf("Failed to write fake MAC!");
        return 0;
    }
    
    log_bpf("Spoofed MAC: %02x:%02x:%02x:%02x:%02x:%02x",
               fake_mac[0], fake_mac[1], fake_mac[2],
               fake_mac[3], fake_mac[4], fake_mac[5]);
    
    // Send event to ringbuffer
    struct mac_spoof_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (event) {
        event->pid = pid_tgid >> 32;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        __builtin_memcpy(event->iface, iface_name, IFNAMSIZ);
        __builtin_memcpy(event->original_mac, original_mac, 6);
        __builtin_memcpy(event->spoofed_mac, (void *)fake_mac, 6);
        event->success = true;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";