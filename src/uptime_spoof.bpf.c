// SPDX-License-Identifier: GPL-2.0
/*
 * uptime_spoof.bpf.c - Spoof /proc/uptime to a configurable large value.
 *
 * Same single-file-rewrite pattern as meminfo_spoof.bpf.c. /proc/uptime's
 * entire content is the two-number line itself (no other lines to
 * preserve), so the whole read buffer is replaced unconditionally once
 * matched - no per-line prefix check needed, unlike /proc/meminfo.
 *
 * Known limitation (documented, not fixed here): this is a static value,
 * not a ticking clock - a sample reading /proc/uptime twice with a real
 * time delay between reads would see the same frozen number both times.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

const volatile char file_uptime[64] = "/proc/uptime";

/* Built in userspace via snprintf, with its exact byte length - same
 * "never hardcode a byte count" discipline as meminfo's fake_memtotal_len. */
const volatile char fake_uptime_line[64] = "259200.00 259200.00\n";
const volatile unsigned int fake_uptime_len = 20;

static __always_inline bool str_match(const char *a, const char *b, int max_len) {
    for (int i = 0; i < max_len; i++) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
    return true;
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    char filename[64];
    bpf_probe_read_user(&filename, sizeof(filename), (char*)ctx->args[1]);

    if (str_match(filename, (const char *)file_uptime, 64)) {
        int file_type = 1;
        bpf_map_update_elem(&map_fds, &pid_tgid, &file_type, BPF_ANY);
    }

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int *pfile_type = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (!pfile_type) return 0;

    if (ctx->ret < 0) {
        bpf_map_delete_elem(&map_fds, &pid_tgid);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int *pfile_type = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (!pfile_type) return 0;

    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &buff_addr, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    int *pfile_type = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (!pfile_type) return 0;

    long unsigned int *pbuff = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (!pbuff) return 0;

    /* Read ctx->ret into a local once and reuse it - re-reading ctx->ret
     * from the tracepoint struct multiple times (as this did before) gives
     * the verifier a fresh, unbounded scalar on each load, so the >0 check
     * below doesn't carry forward to the wlen clamp and bpf_probe_write_user
     * gets rejected with "R3 min value is negative" - same pattern already
     * handled correctly in dmi_spoof.bpf.c's handle_read_exit(). */
    long ret = ctx->ret;
    if (ret <= 0) return 0;

    long unsigned int buff_addr = *pbuff;

    /* Never write more than was actually read, even though our configured
     * line is normally at least as long as the real one. */
    unsigned int wlen = fake_uptime_len;
    if ((long)wlen > ret)
        wlen = (unsigned int)ret;

    bpf_probe_write_user((void*)buff_addr, (void*)fake_uptime_line, wlen);
    log_bpf("[UPTIME] Spoofed /proc/uptime");

    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    return 0;
}
