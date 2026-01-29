// SPDX-License-Identifier: GPL-2.0
/*
 * cpuinfo_spoof.bpf.c - Multi-occurrence replacement using bpf_loop()
 * 
 * This is THE solution to the "8193 jumps too complex" verifier error.
 * 
 * Key insight: bpf_loop() (kernel 5.17+) runs the loop INSIDE the kernel
 * helper, not in the BPF program. The verifier only checks the callback
 * function ONCE, regardless of how many times it executes.
 * 
 * Architecture:
 * 1. On sys_exit_read, call bpf_loop() to scan buffer for patterns
 * 2. Each callback iteration checks one byte position
 * 3. When pattern found, immediately replace it
 * 4. Continue scanning for more occurrences
 *
 * Requires: Linux kernel 5.17+ for bpf_loop() support
 */

 #include "vmlinux.h"
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 
 char LICENSE[] SEC("license") = "GPL";
 
 /* Configuration - can be changed via maps if needed */
 #define MAX_BUF_SIZE 4096
 #define SPOOF_CORES "8"
 #define SPOOF_MICROCODE "0x000000b4"
 
 /* Track which PIDs are reading cpuinfo */
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 4096);
     __type(key, u32);
     __type(value, u8);
 } target_pids SEC(".maps");
 
 /* Store read buffer address between enter/exit */
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 8192);
     __type(key, u64);
     __type(value, unsigned long);
 } read_args SEC(".maps");
 
 /* Context passed to bpf_loop callback */
 struct scan_ctx {
     char *user_buf;      /* User space buffer address */
     int buf_len;         /* Buffer length */
     int replaced_count;  /* How many replacements made */
 };
 
 /* 
  * Check if filename is /proc/cpuinfo
  * Returns 1 if match, 0 otherwise
  */
 static __always_inline int is_cpuinfo(const char *filename)
 {
     char buf[16] = {};
     if (bpf_probe_read_user_str(buf, sizeof(buf), filename) < 0)
         return 0;
     
     /* Check "/proc/cpuinfo" */
     if (buf[0] != '/' || buf[1] != 'p' || buf[2] != 'r' || buf[3] != 'o')
         return 0;
     if (buf[4] != 'c' || buf[5] != '/' || buf[6] != 'c' || buf[7] != 'p')
         return 0;
     if (buf[8] != 'u' || buf[9] != 'i' || buf[10] != 'n' || buf[11] != 'f')
         return 0;
     if (buf[12] != 'o')
         return 0;
     
     return 1;
 }
 
 /*
  * bpf_loop callback - called for each byte position in the buffer
  * 
  * This is where the magic happens. The verifier only analyzes this
  * function ONCE, not for every iteration. So we can scan thousands
  * of bytes without hitting complexity limits.
  *
  * Returns:
  *   0 = continue iterating
  *   1 = stop iterating
  */
 static long scan_callback(u32 index, void *ctx)
 {
     struct scan_ctx *sc = ctx;
     
     /* Bounds check */
     if (index >= sc->buf_len || index >= MAX_BUF_SIZE - 16)
         return 1;  /* Stop */
     
     /* Read a small chunk starting at this position */
     char chunk[16] = {};
     if (bpf_probe_read_user(chunk, 16, sc->user_buf + index) < 0)
         return 0;  /* Continue, just skip this position */
     
     /*
      * Pattern 1: "hypervisor " (11 bytes)
      * Replace with 11 spaces to remove from flags
      */
     if (chunk[0] == 'h' && chunk[1] == 'y' && chunk[2] == 'p' && 
         chunk[3] == 'e' && chunk[4] == 'r' && chunk[5] == 'v' &&
         chunk[6] == 'i' && chunk[7] == 's' && chunk[8] == 'o' && 
         chunk[9] == 'r' && chunk[10] == ' ') {
         
         char spaces[12] = "           ";  /* 11 spaces */
         bpf_probe_write_user(sc->user_buf + index, spaces, 11);
         sc->replaced_count++;
         return 0;  /* Continue scanning for more */
     }
     
     /*
      * Pattern 2: "cpu cores\t: " (12 bytes) followed by digit
      * Replace the digit with '8'
      */
     if (chunk[0] == 'c' && chunk[1] == 'p' && chunk[2] == 'u' && 
         chunk[3] == ' ' && chunk[4] == 'c' && chunk[5] == 'o' &&
         chunk[6] == 'r' && chunk[7] == 'e' && chunk[8] == 's' && 
         chunk[9] == '\t' && chunk[10] == ':' && chunk[11] == ' ') {
         
         /* Check the digit is in range '1'-'9' or multi-digit */
         if (chunk[12] >= '0' && chunk[12] <= '9') {
             char eight = '8';
             bpf_probe_write_user(sc->user_buf + index + 12, &eight, 1);
             sc->replaced_count++;
         }
         return 0;
     }
     
     /*
      * Pattern 3: "siblings\t: " (11 bytes) followed by digit
      * Replace the digit with '8'
      */
     if (chunk[0] == 's' && chunk[1] == 'i' && chunk[2] == 'b' && 
         chunk[3] == 'l' && chunk[4] == 'i' && chunk[5] == 'n' &&
         chunk[6] == 'g' && chunk[7] == 's' && chunk[8] == '\t' && 
         chunk[9] == ':' && chunk[10] == ' ') {
         
         if (chunk[11] >= '0' && chunk[11] <= '9') {
             char eight = '8';
             bpf_probe_write_user(sc->user_buf + index + 11, &eight, 1);
             sc->replaced_count++;
         }
         return 0;
     }
     
     /*
      * Pattern 4: "0xffffffff" (10 bytes) - microcode signature
      * Replace with "0x000000b4"
      */
     if (chunk[0] == '0' && chunk[1] == 'x' && chunk[2] == 'f' && 
         chunk[3] == 'f' && chunk[4] == 'f' && chunk[5] == 'f' &&
         chunk[6] == 'f' && chunk[7] == 'f' && chunk[8] == 'f' && 
         chunk[9] == 'f') {
         
         char mc[10] = "0x000000b4";
         bpf_probe_write_user(sc->user_buf + index, mc, 10);
         sc->replaced_count++;
         return 0;
     }
     
     return 0;  /* Continue scanning */
 }
 
 SEC("tp/syscalls/sys_enter_openat")
 int sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
 {
     const char *filename = (const char *)ctx->args[1];
     if (!is_cpuinfo(filename))
         return 0;
     
     u32 pid = bpf_get_current_pid_tgid() >> 32;
     u8 marker = 1;
     bpf_map_update_elem(&target_pids, &pid, &marker, BPF_ANY);
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_enter_read")
 int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
 {
     u32 pid = bpf_get_current_pid_tgid() >> 32;
     if (!bpf_map_lookup_elem(&target_pids, &pid))
         return 0;
     
     unsigned long buf_addr = ctx->args[1];
     if (buf_addr == 0)
         return 0;
     
     u64 pid_tgid = bpf_get_current_pid_tgid();
     bpf_map_update_elem(&read_args, &pid_tgid, &buf_addr, BPF_ANY);
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_exit_read")
 int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
 {
     u64 pid_tgid = bpf_get_current_pid_tgid();
     
     unsigned long *buf_ptr = bpf_map_lookup_elem(&read_args, &pid_tgid);
     if (!buf_ptr)
         return 0;
     
     unsigned long buf_addr = *buf_ptr;
     bpf_map_delete_elem(&read_args, &pid_tgid);
     
     long ret = ctx->ret;
     if (ret <= 0 || buf_addr == 0)
         return 0;
     
     int len = ret;
     if (len > MAX_BUF_SIZE)
         len = MAX_BUF_SIZE;
     
     /* Set up context for bpf_loop callback */
     struct scan_ctx sc = {
         .user_buf = (char *)buf_addr,
         .buf_len = len,
         .replaced_count = 0,
     };
     
     /*
      * bpf_loop() - the key to bypassing verifier complexity!
      * 
      * Arguments:
      *   nr_loops: maximum iterations (we scan every byte)
      *   callback: function to call for each iteration
      *   callback_ctx: pointer to our context struct
      *   flags: must be 0 currently
      *
      * The verifier only checks the callback ONCE, not per-iteration.
      * So we can scan 4096 bytes without hitting 8193 jump limit!
      */
     bpf_loop(len, scan_callback, &sc, 0);
     
     /* Optional: log how many replacements we made */
     if (sc.replaced_count > 0) {
         bpf_printk("cpuinfo_spoof: made %d replacements", sc.replaced_count);
     }
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_enter_close")
 int sys_enter_close(struct trace_event_raw_sys_enter *ctx)
 {
     u32 pid = bpf_get_current_pid_tgid() >> 32;
     bpf_map_delete_elem(&target_pids, &pid);
     return 0;
 }