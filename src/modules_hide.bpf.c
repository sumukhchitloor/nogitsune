// SPDX-License-Identifier: GPL-2.0
/*
 * modules_hide.bpf.c - Hide kernel modules from /proc/modules
 * 
 * Hides VirtualBox kernel modules (vboxguest, vboxsf, vboxvideo)
 * by replacing their names with spaces when read.
 *
 * /proc/modules format:
 * module_name size used_by [dependencies] state address
 * vboxguest 57344 2 vboxsf, Live 0xffffffffc0a00000
 *
 * We replace "vboxguest" with spaces so tools like lsmod don't see it.
 * The line still exists but the module name is blanked out.
 *
 * Better approach: Replace entire line with newlines to completely remove.
 */

 #include "vmlinux.h"
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 
 char LICENSE[] SEC("license") = "GPL";
 
 #define MAX_BUF_SIZE 8192
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 4096);
     __type(key, u32);
     __type(value, u8);
 } target_pids SEC(".maps");
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 8192);
     __type(key, u64);
     __type(value, unsigned long);
 } read_args SEC(".maps");
 
 static __always_inline int is_proc_modules(const char *filename)
 {
     char buf[16];
     if (bpf_probe_read_user_str(buf, sizeof(buf), filename) < 0)
         return 0;
     
     /* Check "/proc/modules" */
     return (buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r' &&
             buf[3] == 'o' && buf[4] == 'c' && buf[5] == '/' &&
             buf[6] == 'm' && buf[7] == 'o' && buf[8] == 'd' &&
             buf[9] == 'u' && buf[10] == 'l' && buf[11] == 'e' &&
             buf[12] == 's');
 }
 
 /* Context for bpf_loop callback */
 struct scan_ctx {
     char *buf;
     int len;
     int hidden_count;
 };
 
 /*
  * Scan for module names to hide:
  * - vboxguest (9 chars)
  * - vboxsf (6 chars)  
  * - vboxvideo (9 chars)
  *
  * Strategy: When we find the module name at start of line (after newline
  * or at position 0), we overwrite it with spaces. This effectively
  * "blanks" the module name while keeping the line structure intact.
  *
  * For a cleaner hide, we could scan for the entire line and replace
  * it with spaces, but that's more complex.
  */
 static long modules_scan_callback(u32 index, void *ctx)
 {
     struct scan_ctx *sc = ctx;
     
     if (index >= sc->len || index >= MAX_BUF_SIZE - 12)
         return 1;
     
     char chunk[12];
     if (bpf_probe_read_user(chunk, 12, sc->buf + index) < 0)
         return 0;
     
     /* Check if we're at start of line (index 0 or after newline) */
     int at_line_start = 0;
     if (index == 0) {
         at_line_start = 1;
     } else {
         char prev;
         if (bpf_probe_read_user(&prev, 1, sc->buf + index - 1) == 0) {
             if (prev == '\n')
                 at_line_start = 1;
         }
     }
     
     if (!at_line_start)
         return 0;
     
     /* Pattern: "vboxguest " (10 chars with space) */
     if (chunk[0] == 'v' && chunk[1] == 'b' && chunk[2] == 'o' &&
         chunk[3] == 'x' && chunk[4] == 'g' && chunk[5] == 'u' &&
         chunk[6] == 'e' && chunk[7] == 's' && chunk[8] == 't' &&
         chunk[9] == ' ') {
         /* Replace module name with # to comment it visually */
         char repl[10] = "#hidden  ";
         bpf_probe_write_user(sc->buf + index, repl, 9);
         sc->hidden_count++;
         return 0;
     }
     
     /* Pattern: "vboxsf " (7 chars with space) */
     if (chunk[0] == 'v' && chunk[1] == 'b' && chunk[2] == 'o' &&
         chunk[3] == 'x' && chunk[4] == 's' && chunk[5] == 'f' &&
         chunk[6] == ' ') {
         char repl[7] = "#hide ";
         bpf_probe_write_user(sc->buf + index, repl, 6);
         sc->hidden_count++;
         return 0;
     }
     
     /* Pattern: "vboxvideo " (10 chars with space) */
     if (chunk[0] == 'v' && chunk[1] == 'b' && chunk[2] == 'o' &&
         chunk[3] == 'x' && chunk[4] == 'v' && chunk[5] == 'i' &&
         chunk[6] == 'd' && chunk[7] == 'e' && chunk[8] == 'o' &&
         chunk[9] == ' ') {
         char repl[10] = "#hidden  ";
         bpf_probe_write_user(sc->buf + index, repl, 9);
         sc->hidden_count++;
         return 0;
     }
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_enter_openat")
 int sys_enter_openat(struct trace_event_raw_sys_enter *ctx)
 {
     if (!is_proc_modules((const char *)ctx->args[1]))
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
     
     unsigned long buf = ctx->args[1];
     if (buf == 0)
         return 0;
     
     u64 pid_tgid = bpf_get_current_pid_tgid();
     bpf_map_update_elem(&read_args, &pid_tgid, &buf, BPF_ANY);
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_exit_read")
 int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
 {
     u64 pid_tgid = bpf_get_current_pid_tgid();
     
     unsigned long *pbuf = bpf_map_lookup_elem(&read_args, &pid_tgid);
     if (!pbuf)
         return 0;
     
     unsigned long buf = *pbuf;
     bpf_map_delete_elem(&read_args, &pid_tgid);
     
     long ret = ctx->ret;
     if (ret <= 0 || buf == 0)
         return 0;
     
     int len = ret;
     if (len > MAX_BUF_SIZE)
         len = MAX_BUF_SIZE;
     
     struct scan_ctx sc = {
         .buf = (char *)buf,
         .len = len,
         .hidden_count = 0,
     };
     
     bpf_loop(len, modules_scan_callback, &sc, 0);
     
     if (sc.hidden_count > 0) {
         bpf_printk("[MODULES] hidden %d vbox modules", sc.hidden_count);
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