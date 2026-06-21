// SPDX-License-Identifier: GPL-2.0
/*
 * devicetree_spoof.bpf.c - Spoof ARM64 Device Tree hardware identity
 *
 * On ARM64 systems that boot via plain Device Tree (Raspberry Pi, bare
 * QEMU 'virt' machine) rather than UEFI/ACPI, there is no
 * /sys/class/dmi/id - hardware identity instead comes from
 * /proc/device-tree/model and /proc/device-tree/compatible. This mirrors
 * dmi_spoof.bpf.c's per-file replacement pattern for those two files.
 *
 * NOTE: real /proc/device-tree/compatible is a NUL-separated list of
 * compatible strings (e.g. "raspberrypi,4-model-b\0brcm,bcm2711\0"); this
 * tool treats it as a single value for v1 - a documented simplification
 * that's adequate to defeat naive string checks but not a byte-accurate
 * Device Tree compatible list.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

/* File index mapping:
 *  0 = /proc/device-tree/model
 *  1 = /proc/device-tree/compatible
 */
const volatile char fake_model[64]      = "Dell Inc. OptiPlex 7090";
const volatile char fake_compatible[64] = "dell,optiplex-7090";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, int);
} map_file_idx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, unsigned long);
} map_buffs SEC(".maps");

/* Check if filename ends with a specific suffix (reused pattern from
 * dmi_spoof.bpf.c's str_ends_with(), duplicated here per this codebase's
 * existing per-file-helper convention) */
static __always_inline int str_ends_with(const char *path, const char *suffix, int suffix_len)
{
    int path_len = 0;
    for (int i = 0; i < 64; i++) {
        if (path[i] == '\0') {
            path_len = i;
            break;
        }
    }

    if (path_len < suffix_len)
        return 0;

    int start = path_len - suffix_len;
    for (int i = 0; i < suffix_len; i++) {
        if (path[start + i] != suffix[i])
            return 0;
    }
    return 1;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    char filename[64];
    if (bpf_probe_read_user(filename, sizeof(filename), (void *)ctx->args[1]) < 0)
        return 0;

    int file_idx = -1;
    if (str_ends_with(filename, "device-tree/model", 17))
        file_idx = 0;
    else if (str_ends_with(filename, "device-tree/compatible", 22))
        file_idx = 1;

    if (file_idx >= 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        bpf_map_update_elem(&map_file_idx, &pid_tgid, &file_idx, BPF_ANY);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    if (!bpf_map_lookup_elem(&map_file_idx, &pid_tgid))
        return 0;

    unsigned long buf = ctx->args[1];
    if (buf)
        bpf_map_update_elem(&map_buffs, &pid_tgid, &buf, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    int *pfile_idx = bpf_map_lookup_elem(&map_file_idx, &pid_tgid);
    if (!pfile_idx)
        return 0;

    unsigned long *pbuf = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (!pbuf)
        return 0;

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    int file_idx = *pfile_idx;
    char *buf = (char *)*pbuf;

    /* Fixed-width overwrite: write up to the full 64-byte rodata width, but
     * never more than was actually read. fake_model/fake_compatible are
     * NUL-padded in userspace past the configured value, so every byte in
     * [0, wlen) is deterministically replaced regardless of how short the
     * configured replacement is relative to the real string it covers up
     * (same fix as dmi_spoof.bpf.c's fixed-width write). */
    unsigned int wlen = (ret > 64) ? 64 : (unsigned int)ret;

    switch (file_idx) {
        case 0: bpf_probe_write_user(buf, (void *)fake_model, wlen); break;
        case 1: bpf_probe_write_user(buf, (void *)fake_compatible, wlen); break;
    }

    log_bpf("[DEVICETREE] spoofed file_idx=%d", file_idx);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&map_file_idx, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    return 0;
}
