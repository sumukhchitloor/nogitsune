// SPDX-License-Identifier: GPL-2.0
/*
 * cpucount_spoof.bpf.c - Spoof the CPU affinity mask sched_getaffinity()
 * returns, inflating the apparent CPU count for callers like `nproc`
 * (which uses sched_getaffinity by default, not /proc/cpuinfo).
 *
 * This is a structurally different code path from cpuinfo_spoof's cosmetic
 * "cpu cores"/"siblings" text edits - confirmed by grep that nothing else
 * in this codebase touches sched_getaffinity. /sys/devices/system/cpu/<n> and
 * /proc/cpuinfo's processor-line count (the only field ARM64 even has) are
 * separate, still-unaddressed paths - documented limitation, not fixed here.
 *
 * Same fixed-width bpf_probe_write_user pattern as dmi_spoof/meminfo_spoof/
 * uptime_spoof: userspace precomputes the entire replacement mask (all
 * bits [0, fake_cpu_count) set) so the BPF side never needs a runtime
 * loop over a configurable count - avoiding the verifier bound-loss class
 * of bug hit (and fixed) in textreplace.bpf.c this session.
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

#define MASK_BUF_SIZE 32 /* up to 256 simulated CPUs */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, unsigned long);
} map_buf_addr SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, unsigned int);
} map_req_len SEC(".maps");

/* Precomputed in userspace: bits [0, fake_cpu_count) set, rest zero. */
const volatile char fake_affinity_mask[MASK_BUF_SIZE];

SEC("tp/syscalls/sys_enter_sched_getaffinity")
int handle_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned int len = (unsigned int)ctx->args[1];
    unsigned long buf_addr = (unsigned long)ctx->args[2];

    if (buf_addr == 0)
        return 0;

    bpf_map_update_elem(&map_req_len, &pid_tgid, &len, BPF_ANY);
    bpf_map_update_elem(&map_buf_addr, &pid_tgid, &buf_addr, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_sched_getaffinity")
int handle_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned long *pbuf_addr = bpf_map_lookup_elem(&map_buf_addr, &pid_tgid);
    unsigned int *preq_len = bpf_map_lookup_elem(&map_req_len, &pid_tgid);
    bpf_map_delete_elem(&map_buf_addr, &pid_tgid);
    bpf_map_delete_elem(&map_req_len, &pid_tgid);

    if (!pbuf_addr || !preq_len)
        return 0;

    long ret = ctx->ret;
    /* sched_getaffinity() returns the cpumask size in bytes on success,
     * a negative errno on failure. */
    if (ret <= 0)
        return 0;

    unsigned long buf_addr = *pbuf_addr;
    unsigned int req_len = *preq_len;

    /* Never write past the smaller of: the caller's buffer size, the
     * kernel's own fill size, and our fixed mask width. */
    unsigned int wlen = MASK_BUF_SIZE;
    if (req_len < wlen)
        wlen = req_len;
    if ((unsigned long)ret < wlen)
        wlen = (unsigned int)ret;

    /* bpf_probe_write_user's size arg must be verifier-provably >= 1
     * ("invalid zero-sized read" otherwise) - the clamps above only prove
     * wlen is in [0, MASK_BUF_SIZE), so rule out 0 explicitly rather than
     * relying on req_len/ret never actually being 0 at runtime. */
    if (wlen == 0)
        return 0;

    bpf_probe_write_user((void *)buf_addr, (void *)fake_affinity_mask, wlen);
    log_bpf("[CPUCOUNT] Spoofed sched_getaffinity mask (%u bytes)", wlen);

    return 0;
}
