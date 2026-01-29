// SPDX-License-Identifier: GPL-2.0
// PCI Device ID Spoofing BPF Program
// Spoofs VirtualBox PCI vendor/device IDs to appear as Intel hardware
//
// Simplified version that uses filename-based tracking instead of FD resolution

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_BUFFER_SIZE 64
#define TASK_COMM_LEN 16

char LICENSE[] SEC("license") = "GPL";

// Track read operations by storing buffer pointer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);   // PID
    __type(value, u64); // Buffer pointer
} read_buf_tracker SEC(".maps");

// Simple string matching for PCI files
static __always_inline int is_pci_file(const char *name) {
    // Check if filename is "vendor" or "device"
    if (!name) return 0;
    
    // Check for "vendor"
    if (name[0] == 'v' && name[1] == 'e' && name[2] == 'n' && 
        name[3] == 'd' && name[4] == 'o' && name[5] == 'r' && name[6] == '\0') {
        return 1;
    }
    
    // Check for "device"  
    if (name[0] == 'd' && name[1] == 'e' && name[2] == 'v' &&
        name[3] == 'i' && name[4] == 'c' && name[5] == 'e' && name[6] == '\0') {
        return 1;
    }
    
    return 0;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get filename from args
    const char *filename = (const char *)ctx->args[1];
    if (!filename) return 0;
    
    char fname[256];
    bpf_probe_read_user_str(fname, sizeof(fname), filename);
    
    // Check if it's a PCI sysfs file
    // Look for pattern: /sys/bus/pci/devices/.../vendor or .../device
    int is_sys = 0, is_bus = 0, is_pci = 0, is_devices = 0;
    int vendor_or_device = 0;
    
    #pragma unroll
    for (int i = 0; i < 240; i++) {
        if (fname[i] == '\0') break;
        
        // Check for /sys/bus/pci/devices/ prefix
        if (i == 0 && fname[i] == '/' && fname[i+1] == 's' && 
            fname[i+2] == 'y' && fname[i+3] == 's') {
            is_sys = 1;
        }
        if (is_sys && fname[i] == 'b' && fname[i+1] == 'u' && fname[i+2] == 's') {
            is_bus = 1;
        }
        if (is_bus && fname[i] == 'p' && fname[i+1] == 'c' && fname[i+2] == 'i') {
            is_pci = 1;
        }
        if (is_pci && fname[i] == 'd' && fname[i+1] == 'e' && fname[i+2] == 'v' &&
            fname[i+3] == 'i' && fname[i+4] == 'c' && fname[i+5] == 'e' && fname[i+6] == 's') {
            is_devices = 1;
        }
        
        // Look for /vendor or /device at end
        if (is_devices && fname[i] == '/') {
            if (fname[i+1] == 'v' && fname[i+2] == 'e' && fname[i+3] == 'n' &&
                fname[i+4] == 'd' && fname[i+5] == 'o' && fname[i+6] == 'r') {
                vendor_or_device = 1;
                break;
            }
            if (fname[i+1] == 'd' && fname[i+2] == 'e' && fname[i+3] == 'v' &&
                fname[i+4] == 'i' && fname[i+5] == 'c' && fname[i+6] == 'e') {
                vendor_or_device = 1;
                break;
            }
        }
    }
    
    // Mark this PID as one to watch
    if (vendor_or_device) {
        u64 marker = 1;
        bpf_map_update_elem(&read_buf_tracker, &pid, &marker, BPF_ANY);
    }
    
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    // Check if this PID opened a PCI file
    u64 *marker = bpf_map_lookup_elem(&read_buf_tracker, &pid);
    if (!marker) return 0;
    
    // Store the buffer pointer for this read
    u64 buf_ptr = ctx->args[1];
    bpf_map_update_elem(&read_buf_tracker, &pid, &buf_ptr, BPF_ANY);
    
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    long ret = ctx->ret;
    
    // Check if we tracked this PID
    u64 *buf_ptr = bpf_map_lookup_elem(&read_buf_tracker, &pid);
    if (!buf_ptr || *buf_ptr == 1) {
        return 0; // No buffer or just marker
    }
    
    // Only process successful small reads
    if (ret <= 0 || ret > MAX_BUFFER_SIZE) {
        bpf_map_delete_elem(&read_buf_tracker, &pid);
        return 0;
    }
    
    // Read the buffer content
    char content[MAX_BUFFER_SIZE];
    __builtin_memset(content, 0, sizeof(content));
    void *buf = (void *)*buf_ptr;
    bpf_probe_read_user(content, ret < sizeof(content) ? ret : sizeof(content), buf);
    
    // Check for VirtualBox vendor ID: 0x80ee -> Intel: 0x8086
    if (ret >= 7 && content[0] == '0' && content[1] == 'x' &&
        content[2] == '8' && content[3] == '0' &&
        content[4] == 'e' && content[5] == 'e') {
        char spoofed[] = "0x8086\n";
        bpf_probe_write_user(buf, spoofed, 7);
    }
    // VirtualBox device: 0xbeef -> Intel: 0x1234
    else if (ret >= 7 && content[0] == '0' && content[1] == 'x' &&
             content[2] == 'b' && content[3] == 'e' &&
             content[4] == 'e' && content[5] == 'f') {
        char spoofed[] = "0x1234\n";
        bpf_probe_write_user(buf, spoofed, 7);
    }
    // VirtualBox device: 0xcafe -> Intel: 0x5678
    else if (ret >= 7 && content[0] == '0' && content[1] == 'x' &&
             content[2] == 'c' && content[3] == 'a' &&
             content[4] == 'f' && content[5] == 'e') {
        char spoofed[] = "0x5678\n";
        bpf_probe_write_user(buf, spoofed, 7);
    }
    // VirtualBox device: 0x0021 -> Intel: 0x1000
    else if (ret >= 7 && content[0] == '0' && content[1] == 'x' &&
             content[2] == '0' && content[3] == '0' &&
             content[4] == '2' && content[5] == '1') {
        char spoofed[] = "0x1000\n";
        bpf_probe_write_user(buf, spoofed, 7);
    }
    // VirtualBox device: 0x0022 -> Intel: 0x1001
    else if (ret >= 7 && content[0] == '0' && content[1] == 'x' &&
             content[2] == '0' && content[3] == '0' &&
             content[4] == '2' && content[5] == '2') {
        char spoofed[] = "0x1001\n";
        bpf_probe_write_user(buf, spoofed, 7);
    }
    
    bpf_map_delete_elem(&read_buf_tracker, &pid);
    return 0;
}