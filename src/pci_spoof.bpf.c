// SPDX-License-Identifier: GPL-2.0
// PCI Device ID Spoofing BPF Program
// Spoofs configurable VirtualBox PCI vendor/device IDs to appear as
// configurable replacement IDs (defaults to Intel hardware IDs).
//
// Simplified version that uses filename-based tracking instead of FD resolution

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define MAX_BUFFER_SIZE 64
#define MAX_PCI_MAPPINGS 8

char LICENSE[] SEC("license") = "GPL";

// Track read operations by storing buffer pointer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);   // pid_tgid
    __type(value, u64); // Buffer pointer
} read_buf_tracker SEC(".maps");

// Configurable vendor/device ID mappings. Each is a fixed "0xXXXX" (6 char)
// pattern - PCI IDs are always this exact width, so unlike DMI/meminfo
// there's no variable-length write risk here.
const volatile int num_pci_mappings = 0;
const volatile char pci_from[MAX_PCI_MAPPINGS][7];
const volatile char pci_to[MAX_PCI_MAPPINGS][8];

SEC("tp/syscalls/sys_enter_openat")
int handle_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

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
        bpf_map_update_elem(&read_buf_tracker, &pid_tgid, &marker, BPF_ANY);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();

    // Check if this PID opened a PCI file
    u64 *marker = bpf_map_lookup_elem(&read_buf_tracker, &pid_tgid);
    if (!marker) return 0;

    // Store the buffer pointer for this read
    u64 buf_ptr = ctx->args[1];
    bpf_map_update_elem(&read_buf_tracker, &pid_tgid, &buf_ptr, BPF_ANY);

    return 0;
}

/* Compare the 6-char "0xXXXX" pattern at content[0..5] against mapping idx.
 * Manual unroll since BPF can't index a 2D rodata array with a runtime idx
 * the verifier can't bound - same approach as pidhide.bpf.c's cmp_pid(). */
static __always_inline int cmp_pci_from(const char *content, int idx) {
    if (content[0] != pci_from[idx][0]) return 0;
    if (content[1] != pci_from[idx][1]) return 0;
    if (content[2] != pci_from[idx][2]) return 0;
    if (content[3] != pci_from[idx][3]) return 0;
    if (content[4] != pci_from[idx][4]) return 0;
    if (content[5] != pci_from[idx][5]) return 0;
    return 1;
}

/* If mapping idx matches, write its replacement (7 bytes: "0xXXXX\n") and
 * return 1. Returns 0 on no match so the caller can try the next index. */
static __always_inline int try_spoof_pci(void *buf, const char *content, int idx) {
    if (!cmp_pci_from(content, idx)) return 0;
    bpf_probe_write_user(buf, (void *)pci_to[idx], 7);
    return 1;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    long ret = ctx->ret;

    // Check if we tracked this PID
    u64 *buf_ptr = bpf_map_lookup_elem(&read_buf_tracker, &pid_tgid);
    if (!buf_ptr || *buf_ptr == 1) {
        return 0; // No buffer or just marker
    }

    // Only process successful small reads, and only if long enough to
    // contain a full "0xXXXX\n" (7 byte) value
    if (ret < 7 || ret > MAX_BUFFER_SIZE) {
        bpf_map_delete_elem(&read_buf_tracker, &pid_tgid);
        return 0;
    }

    // Read the buffer content
    char content[MAX_BUFFER_SIZE];
    __builtin_memset(content, 0, sizeof(content));
    void *buf = (void *)*buf_ptr;
    bpf_probe_read_user(content, ret < sizeof(content) ? ret : sizeof(content), buf);

    // Manually-unrolled bounded loop over configured mappings (mirrors
    // pidhide.bpf.c's check_pid_match() pattern)
    if (num_pci_mappings > 0 && try_spoof_pci(buf, content, 0)) goto done;
    if (num_pci_mappings > 1 && try_spoof_pci(buf, content, 1)) goto done;
    if (num_pci_mappings > 2 && try_spoof_pci(buf, content, 2)) goto done;
    if (num_pci_mappings > 3 && try_spoof_pci(buf, content, 3)) goto done;
    if (num_pci_mappings > 4 && try_spoof_pci(buf, content, 4)) goto done;
    if (num_pci_mappings > 5 && try_spoof_pci(buf, content, 5)) goto done;
    if (num_pci_mappings > 6 && try_spoof_pci(buf, content, 6)) goto done;
    if (num_pci_mappings > 7 && try_spoof_pci(buf, content, 7)) goto done;

done:
    bpf_map_delete_elem(&read_buf_tracker, &pid_tgid);
    return 0;
}
