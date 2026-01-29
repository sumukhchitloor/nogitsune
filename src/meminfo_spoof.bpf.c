// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

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

const volatile char file_meminfo[64] = "/proc/meminfo";

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
    
    if (str_match(filename, file_meminfo, 64)) {
        int file_type = 1;  // meminfo
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
    
    if (ctx->ret <= 0) return 0;
    
    long unsigned int buff_addr = *pbuff;
    
    // MemTotal is first line
    char line[64];
    bpf_probe_read_user(line, 64, (void*)buff_addr);
    
    // Check if starts with "MemTotal:"
    if (line[0] == 'M' && line[1] == 'e' && line[2] == 'm' && 
        line[3] == 'T' && line[4] == 'o' && line[5] == 't' &&
        line[6] == 'a' && line[7] == 'l' && line[8] == ':') {
        
        // Replace with 16GB
        bpf_probe_write_user((void*)buff_addr, 
                            "MemTotal:       16384000 kB\n", 29);
        
        bpf_printk("[MEMINFO] Spoofed to 16GB");
    }
    
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