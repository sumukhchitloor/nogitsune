// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/*
 * fshide.bpf.c - Hide arbitrary filenames from any directory listing.
 *
 * Generalizes pidhide.bpf.c's getdents64/d_reclen-splice technique (which
 * only hides numeric PID directory names under /proc) to arbitrary
 * filename PREFIXES in any directory - e.g. hiding a
 * "VBoxGuestAdditions-7.2.2" install directory from `ls /opt`, or
 * "vboxguest.ko" from a kernel modules directory listing.
 *
 * This only defeats *enumeration* (ls/find/readdir) - a caller that already
 * knows the exact path can still open/stat it directly. That gap is what
 * the separate pathdeny (BPF LSM) tool addresses.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// RingBuffer to send events to userspace
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// Map to hold the dents buffer addresses
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buffs SEC(".maps");

// Map used to enable searching through the data in a loop
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

// Map with address of the previous dirent, for d_reclen patching
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// System-wide - no target_ppid restriction, matching modules_hide's scope
// (every getdents64 call is checked against the configured name list).
#define MAX_HIDDEN_NAMES 16
#define MAX_NAME_LEN 32

const volatile int num_hidden_names = 0;
const volatile char hidden_names[MAX_HIDDEN_NAMES][MAX_NAME_LEN];
const volatile int name_lens[MAX_HIDDEN_NAMES];

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

// Compares filename[0..len-1] against hidden_names[idx][0..len-1] - a
// PREFIX match (e.g. configured "VBoxGuestAdditions" matches the directory
// entry "VBoxGuestAdditions-7.2.2"), mirroring modules_hide.bpf.c's
// array+count+manual-unroll convention rather than pidhide's fixed-digit one
// (filenames are arbitrary length, not bounded to a PID's digit count).
static __always_inline int cmp_name(char *filename, int idx) {
    int len = name_lens[idx];
    if (len <= 0 || len > MAX_NAME_LEN) {
        return 0;
    }

    if (len > 0  && filename[0]  != hidden_names[idx][0])  return 0;
    if (len > 1  && filename[1]  != hidden_names[idx][1])  return 0;
    if (len > 2  && filename[2]  != hidden_names[idx][2])  return 0;
    if (len > 3  && filename[3]  != hidden_names[idx][3])  return 0;
    if (len > 4  && filename[4]  != hidden_names[idx][4])  return 0;
    if (len > 5  && filename[5]  != hidden_names[idx][5])  return 0;
    if (len > 6  && filename[6]  != hidden_names[idx][6])  return 0;
    if (len > 7  && filename[7]  != hidden_names[idx][7])  return 0;
    if (len > 8  && filename[8]  != hidden_names[idx][8])  return 0;
    if (len > 9  && filename[9]  != hidden_names[idx][9])  return 0;
    if (len > 10 && filename[10] != hidden_names[idx][10]) return 0;
    if (len > 11 && filename[11] != hidden_names[idx][11]) return 0;
    if (len > 12 && filename[12] != hidden_names[idx][12]) return 0;
    if (len > 13 && filename[13] != hidden_names[idx][13]) return 0;
    if (len > 14 && filename[14] != hidden_names[idx][14]) return 0;
    if (len > 15 && filename[15] != hidden_names[idx][15]) return 0;
    if (len > 16 && filename[16] != hidden_names[idx][16]) return 0;
    if (len > 17 && filename[17] != hidden_names[idx][17]) return 0;
    if (len > 18 && filename[18] != hidden_names[idx][18]) return 0;
    if (len > 19 && filename[19] != hidden_names[idx][19]) return 0;
    if (len > 20 && filename[20] != hidden_names[idx][20]) return 0;
    if (len > 21 && filename[21] != hidden_names[idx][21]) return 0;
    if (len > 22 && filename[22] != hidden_names[idx][22]) return 0;
    if (len > 23 && filename[23] != hidden_names[idx][23]) return 0;
    if (len > 24 && filename[24] != hidden_names[idx][24]) return 0;
    if (len > 25 && filename[25] != hidden_names[idx][25]) return 0;
    if (len > 26 && filename[26] != hidden_names[idx][26]) return 0;
    if (len > 27 && filename[27] != hidden_names[idx][27]) return 0;
    if (len > 28 && filename[28] != hidden_names[idx][28]) return 0;
    if (len > 29 && filename[29] != hidden_names[idx][29]) return 0;
    if (len > 30 && filename[30] != hidden_names[idx][30]) return 0;
    if (len > 31 && filename[31] != hidden_names[idx][31]) return 0;

    return 1;
}

// Manual unroll for MAX_HIDDEN_NAMES (16) - each check independent, mirrors
// pidhide.bpf.c's check_pid_match().
static __always_inline int check_name_match(char *filename) {
    if (num_hidden_names > 0  && cmp_name(filename, 0))  return 1;
    if (num_hidden_names > 1  && cmp_name(filename, 1))  return 1;
    if (num_hidden_names > 2  && cmp_name(filename, 2))  return 1;
    if (num_hidden_names > 3  && cmp_name(filename, 3))  return 1;
    if (num_hidden_names > 4  && cmp_name(filename, 4))  return 1;
    if (num_hidden_names > 5  && cmp_name(filename, 5))  return 1;
    if (num_hidden_names > 6  && cmp_name(filename, 6))  return 1;
    if (num_hidden_names > 7  && cmp_name(filename, 7))  return 1;
    if (num_hidden_names > 8  && cmp_name(filename, 8))  return 1;
    if (num_hidden_names > 9  && cmp_name(filename, 9))  return 1;
    if (num_hidden_names > 10 && cmp_name(filename, 10)) return 1;
    if (num_hidden_names > 11 && cmp_name(filename, 11)) return 1;
    if (num_hidden_names > 12 && cmp_name(filename, 12)) return 1;
    if (num_hidden_names > 13 && cmp_name(filename, 13)) return 1;
    if (num_hidden_names > 14 && cmp_name(filename, 14)) return 1;
    if (num_hidden_names > 15 && cmp_name(filename, 15)) return 1;

    return 0;
}

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
    bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int total_bytes_read = ctx->ret;

    if (total_bytes_read <= 0) {
        return 0;
    }

    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp = 0;
    short unsigned int d_reclen = 0;
    char filename[MAX_NAME_LEN];

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

        if (check_name_match(filename)) {
            unsigned int next_pos = bpos + d_reclen;
            bpf_map_update_elem(&map_bytes_read, &pid_tgid, &next_pos, BPF_ANY);
            bpf_tail_call(ctx, &map_prog_array, PROG_02);
        }

        bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
        bpos += d_reclen;
    }

    if (bpos < total_bytes_read) {
        bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
        bpf_tail_call(ctx, &map_prog_array, PROG_01);
    }

    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);
    bpf_map_delete_elem(&map_to_patch, &pid_tgid);

    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
    short unsigned int d_reclen_previous = 0;
    bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

    struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr + d_reclen_previous);
    short unsigned int d_reclen = 0;
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

    char filename[MAX_NAME_LEN];
    bpf_probe_read_user_str(&filename, sizeof(filename), dirp_previous->d_name);
    log_bpf("[FSHIDE] previous entry: %s\n", filename);
    bpf_probe_read_user_str(&filename, sizeof(filename), dirp->d_name);
    log_bpf("[FSHIDE] hiding entry: %s\n", filename);

    short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
    long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = (pid_tgid >> 32);
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }

    bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp_previous, BPF_ANY);

    bpf_tail_call(ctx, &map_prog_array, PROG_01);

    bpf_map_delete_elem(&map_to_patch, &pid_tgid);
    bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
    bpf_map_delete_elem(&map_buffs, &pid_tgid);

    return 0;
}
