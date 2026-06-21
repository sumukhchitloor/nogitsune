// SPDX-License-Identifier: GPL-2.0
/*
 * kmsg_spoof.bpf.c - Live kernel-log sanitization.
 *
 * Two hook points, confirmed via live prototyping (not assumed) to need
 * different techniques:
 *
 *  - /dev/kmsg (openat+read tracepoints): each read() returns exactly ONE
 *    self-contained message ("facility,seq,timestamp_us,flags;text\n"),
 *    confirmed empirically - never multiple messages packed together,
 *    never split across reads.
 *  - legacy syslog()/klogctl syscall (SYSLOG_ACTION_READ_ALL): confirmed
 *    to return the ENTIRE current ring buffer in one call (multi-KB,
 *    many lines, different "<priority>[timestamp] text" format) - this
 *    needs the same bpf_loop() multi-pattern scanner dmi_spoof's
 *    modalias scanner (and A2's raw-SMBIOS extension of it) already use,
 *    and shares that same verifier-bound risk on a runtime-sized buffer.
 *
 * HARD LIMITATION (documented, not fixable here): this only sanitizes
 * LIVE reads of the kernel ring buffer. It does NOT retroactively scrub
 * VBoxGuest/VBoxService boot messages systemd already archived into
 * /var/log/journal/.../system.journal before this tool started - those
 * are static binary files read directly, not a syscall this process can
 * intercept. Mitigation is rotating/vacuuming the journal as a
 * pre-analysis setup step, not something this tool attempts.
 *
 * Patterns are hardcoded (not configurable), same scope-trim reasoning
 * as dmi_spoof's modalias/uevent scanner: these are exact-byte-length
 * embedded substring blanks, not single-value replacements - making them
 * configurable would mean silently truncating/padding arbitrary strings.
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

#define KMSG_BUF_SIZE 1024  /* one /dev/kmsg record, confirmed bounded */
#define SYSLOG_BUF_SIZE 4096 /* legacy syslog() can return the whole ring buffer */

const volatile char file_kmsg[16] = "/dev/kmsg";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u8);
} kmsg_fds SEC(".maps");

static __always_inline bool str_match(const char *a, const char *b, int max_len) {
    for (int i = 0; i < max_len; i++) {
        if (a[i] != b[i]) return false;
        if (a[i] == '\0') return true;
    }
    return true;
}

struct scan_ctx {
    char *buf;
    int len;
    int count;
};

/* Shared by both /dev/kmsg (KMSG_BUF_SIZE-bounded calls) and the legacy
 * syslog() path (SYSLOG_BUF_SIZE-bounded calls) - the bound check below
 * uses sc->len (the actual per-call length, already capped by the
 * caller to whichever buffer size applies), not a hardcoded constant. */
static long pattern_scan_callback(u32 index, void *ctx)
{
    struct scan_ctx *sc = ctx;

    if (index >= sc->len || index >= SYSLOG_BUF_SIZE - 12)
        return 1;

    char chunk[12];
    if (bpf_probe_read_user(chunk, 12, sc->buf + index) < 0)
        return 0;

    /* "vbox"/"VBox"/"VBOX"/etc - case-insensitive on all 4 letters, one
     * pattern instead of separately hardcoding every case combination. */
    char c0 = chunk[0], c1 = chunk[1], c2 = chunk[2], c3 = chunk[3];
    if ((c0 == 'V' || c0 == 'v') && (c1 == 'B' || c1 == 'b') &&
        (c2 == 'O' || c2 == 'o') && (c3 == 'X' || c3 == 'x')) {
        char repl[4] = "    ";
        bpf_probe_write_user(sc->buf + index, repl, 4);
        sc->count++;
        return 0;
    }

    /* "VirtualBox" (10 chars) - exact case, matching dmi_spoof's modalias
     * scanner convention for this same token. */
    if (chunk[0] == 'V' && chunk[1] == 'i' && chunk[2] == 'r' && chunk[3] == 't' &&
        chunk[4] == 'u' && chunk[5] == 'a' && chunk[6] == 'l' && chunk[7] == 'B' &&
        chunk[8] == 'o' && chunk[9] == 'x') {
        char repl[10] = "          ";
        bpf_probe_write_user(sc->buf + index, repl, 10);
        sc->count++;
        return 0;
    }

    return 0;
}

/* ============ /dev/kmsg ============ */

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    char filename[16];
    if (bpf_probe_read_user(filename, sizeof(filename), (void *)ctx->args[1]) < 0)
        return 0;

    if (str_match(filename, (const char *)file_kmsg, 16)) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u8 marker = 1;
        bpf_map_update_elem(&kmsg_fds, &pid_tgid, &marker, BPF_ANY);
    }

    return 0;
}

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, unsigned long);
} kmsg_read_bufs SEC(".maps");

SEC("tp/syscalls/sys_enter_read")
int handle_kmsg_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    if (!bpf_map_lookup_elem(&kmsg_fds, &pid_tgid))
        return 0;

    unsigned long buf_addr = (unsigned long)ctx->args[1];
    if (buf_addr == 0)
        return 0;

    bpf_map_update_elem(&kmsg_read_bufs, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_kmsg_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned long *pbuf = bpf_map_lookup_elem(&kmsg_read_bufs, &pid_tgid);
    if (!pbuf)
        return 0;

    unsigned long buf_addr = *pbuf;
    bpf_map_delete_elem(&kmsg_read_bufs, &pid_tgid);

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    int len = ret;
    if (len > KMSG_BUF_SIZE)
        len = KMSG_BUF_SIZE;

    struct scan_ctx sc = {
        .buf = (char *)buf_addr,
        .len = len,
        .count = 0,
    };
    bpf_loop(len, pattern_scan_callback, &sc, 0);

    if (sc.count > 0) {
        log_bpf("[KMSG] /dev/kmsg: blanked %d pattern(s)", sc.count);
    }

    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&kmsg_fds, &pid_tgid);
    bpf_map_delete_elem(&kmsg_read_bufs, &pid_tgid);
    return 0;
}

/* ============ legacy syslog()/klogctl ============ */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, unsigned long);
} syslog_bufs SEC(".maps");

SEC("tp/syscalls/sys_enter_syslog")
int handle_syslog_enter(struct trace_event_raw_sys_enter *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned long buf_addr = (unsigned long)ctx->args[1];
    if (buf_addr == 0)
        return 0;

    bpf_map_update_elem(&syslog_bufs, &pid_tgid, &buf_addr, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_syslog")
int handle_syslog_exit(struct trace_event_raw_sys_exit *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    unsigned long *pbuf = bpf_map_lookup_elem(&syslog_bufs, &pid_tgid);
    if (!pbuf)
        return 0;

    unsigned long buf_addr = *pbuf;
    bpf_map_delete_elem(&syslog_bufs, &pid_tgid);

    long ret = ctx->ret;
    if (ret <= 0)
        return 0;

    int len = ret;
    if (len > SYSLOG_BUF_SIZE)
        len = SYSLOG_BUF_SIZE;

    struct scan_ctx sc = {
        .buf = (char *)buf_addr,
        .len = len,
        .count = 0,
    };
    bpf_loop(len, pattern_scan_callback, &sc, 0);

    if (sc.count > 0) {
        log_bpf("[KMSG] syslog(): blanked %d pattern(s)", sc.count);
    }

    return 0;
}
