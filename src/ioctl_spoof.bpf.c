// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define SIOCGIFHWADDR 0x8927
#define IFNAMSIZ 16

// Target interface to spoof
const char target_iface[IFNAMSIZ] = "eth0";

// Fake MAC address (Dell OUI: a4:5e:60:xx:xx:xx)
const unsigned char fake_mac[6] = {0xa4, 0x5e, 0x60, 0x12, 0x34, 0x56};

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

SEC("kprobe/__x64_sys_ioctl")
int BPF_KPROBE(ioctl_entry, struct pt_regs *regs)
{
    // For __x64_sys_ioctl, parameters are in pt_regs structure
    // regs->di = fd
    // regs->si = cmd
    // regs->dx = arg (ifreq pointer)
    
    unsigned int cmd = (unsigned int)PT_REGS_PARM2_CORE(regs);  // cmd from rsi
    unsigned long arg = (unsigned long)PT_REGS_PARM3_CORE(regs); // arg from rdx
    
    bpf_printk("ioctl called: cmd=0x%x SIOCGIFHWADDR=0x%x", cmd, SIOCGIFHWADDR);
    
    // Check if this is SIOCGIFHWADDR (get hardware address)
    if (cmd != SIOCGIFHWADDR) {
        return 0;
    }
    
    bpf_printk("SIOCGIFHWADDR detected! arg=0x%lx", arg);
    
    // Store the ifreq pointer for the return probe
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&pending_ioctls, &pid_tgid, &arg, BPF_ANY);
    
    return 0;
}

SEC("kretprobe/__x64_sys_ioctl")
int BPF_KRETPROBE(ioctl_exit, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if this was a SIOCGIFHWADDR call we're tracking
    unsigned long *arg_ptr = bpf_map_lookup_elem(&pending_ioctls, &pid_tgid);
    if (!arg_ptr) {
        return 0;
    }
    
    unsigned long arg = *arg_ptr;
    bpf_map_delete_elem(&pending_ioctls, &pid_tgid);
    
    // Only modify if ioctl succeeded
    if (ret < 0) {
        bpf_printk("ioctl failed with ret=%d, skipping", ret);
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
        bpf_printk("Failed to read interface name");
        return 0;
    }
    
    bpf_printk("Interface: %s", iface_name);
    
    // Check if this is the target interface (eth0)
    bool is_target = true;
    for (int i = 0; i < IFNAMSIZ && target_iface[i] != '\0'; i++) {
        if (iface_name[i] != target_iface[i]) {
            is_target = false;
            break;
        }
    }
    
    if (!is_target) {
        bpf_printk("Not target interface, skipping");
        return 0;
    }
    
    bpf_printk("Target interface matched! Spoofing MAC...");
    
    // Read original MAC address for logging
    unsigned char original_mac[6] = {};
    unsigned long mac_offset = arg + 18; // ifr_name(16) + sa_family(2)
    bpf_probe_read_user(original_mac, 6, (void *)mac_offset);
    
    bpf_printk("Original MAC: %02x:%02x:%02x:%02x:%02x:%02x",
               original_mac[0], original_mac[1], original_mac[2],
               original_mac[3], original_mac[4], original_mac[5]);
    
    // Write fake MAC address
    if (bpf_probe_write_user((void *)mac_offset, fake_mac, 6) < 0) {
        bpf_printk("Failed to write fake MAC!");
        return 0;
    }
    
    bpf_printk("Spoofed MAC: %02x:%02x:%02x:%02x:%02x:%02x",
               fake_mac[0], fake_mac[1], fake_mac[2],
               fake_mac[3], fake_mac[4], fake_mac[5]);
    
    // Send event to ringbuffer
    struct mac_spoof_event *event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
    if (event) {
        event->pid = pid_tgid >> 32;
        bpf_get_current_comm(&event->comm, sizeof(event->comm));
        __builtin_memcpy(event->iface, iface_name, IFNAMSIZ);
        __builtin_memcpy(event->original_mac, original_mac, 6);
        __builtin_memcpy(event->spoofed_mac, fake_mac, 6);
        event->success = true;
        bpf_ringbuf_submit(event, 0);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";