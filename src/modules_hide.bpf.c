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

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif
 
 #define MAX_BUF_SIZE 8192
 #define MAX_MODULES_TO_HIDE 8
 #define MAX_MODULE_NAME_LEN 32

 /* Each entry stores "<name> " (the module name plus its trailing space
  * separator from /proc/modules' "name size used_by ..." format) so a
  * single bounded comparison both matches the name AND confirms it's
  * followed by a separator, not just a longer name sharing the prefix.
  * module_name_lens[i] is strlen(name)+1 (name plus that trailing space). */
 const volatile int num_modules_to_hide = 0;
 const volatile char modules_to_hide[MAX_MODULES_TO_HIDE][MAX_MODULE_NAME_LEN];
 const volatile int module_name_lens[MAX_MODULES_TO_HIDE];

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
 
 /* Fixed source buffer of spaces to blank a matched module name with -
  * length of the write is bounded/runtime but the source is always wide
  * enough (same precedent as text_len in textreplace.bpf.c). */
 static const char blank_spaces[MAX_MODULE_NAME_LEN] =
     "                               ";

 /* Compares chunk[0..len-1] against modules_to_hide[idx][0..len-1], where
  * len = module_name_lens[idx] (name + trailing space). Manual unroll with
  * compile-time indices, mirroring pidhide.bpf.c's cmp_pid(). */
 static __always_inline int cmp_module(const char *chunk, int idx)
 {
     int len = module_name_lens[idx];
     if (len <= 1 || len > MAX_MODULE_NAME_LEN - 1)
         return 0;

     if (len > 0  && chunk[0]  != modules_to_hide[idx][0])  return 0;
     if (len > 1  && chunk[1]  != modules_to_hide[idx][1])  return 0;
     if (len > 2  && chunk[2]  != modules_to_hide[idx][2])  return 0;
     if (len > 3  && chunk[3]  != modules_to_hide[idx][3])  return 0;
     if (len > 4  && chunk[4]  != modules_to_hide[idx][4])  return 0;
     if (len > 5  && chunk[5]  != modules_to_hide[idx][5])  return 0;
     if (len > 6  && chunk[6]  != modules_to_hide[idx][6])  return 0;
     if (len > 7  && chunk[7]  != modules_to_hide[idx][7])  return 0;
     if (len > 8  && chunk[8]  != modules_to_hide[idx][8])  return 0;
     if (len > 9  && chunk[9]  != modules_to_hide[idx][9])  return 0;
     if (len > 10 && chunk[10] != modules_to_hide[idx][10]) return 0;
     if (len > 11 && chunk[11] != modules_to_hide[idx][11]) return 0;
     if (len > 12 && chunk[12] != modules_to_hide[idx][12]) return 0;
     if (len > 13 && chunk[13] != modules_to_hide[idx][13]) return 0;
     if (len > 14 && chunk[14] != modules_to_hide[idx][14]) return 0;
     if (len > 15 && chunk[15] != modules_to_hide[idx][15]) return 0;
     if (len > 16 && chunk[16] != modules_to_hide[idx][16]) return 0;
     if (len > 17 && chunk[17] != modules_to_hide[idx][17]) return 0;
     if (len > 18 && chunk[18] != modules_to_hide[idx][18]) return 0;
     if (len > 19 && chunk[19] != modules_to_hide[idx][19]) return 0;
     if (len > 20 && chunk[20] != modules_to_hide[idx][20]) return 0;
     if (len > 21 && chunk[21] != modules_to_hide[idx][21]) return 0;
     if (len > 22 && chunk[22] != modules_to_hide[idx][22]) return 0;
     if (len > 23 && chunk[23] != modules_to_hide[idx][23]) return 0;
     if (len > 24 && chunk[24] != modules_to_hide[idx][24]) return 0;
     if (len > 25 && chunk[25] != modules_to_hide[idx][25]) return 0;
     if (len > 26 && chunk[26] != modules_to_hide[idx][26]) return 0;
     if (len > 27 && chunk[27] != modules_to_hide[idx][27]) return 0;
     if (len > 28 && chunk[28] != modules_to_hide[idx][28]) return 0;
     if (len > 29 && chunk[29] != modules_to_hide[idx][29]) return 0;
     if (len > 30 && chunk[30] != modules_to_hide[idx][30]) return 0;

     return 1;
 }

 /* If mapping idx matches at this position, blank the name (not the
  * trailing separator space it was matched against) and return 1. */
 static __always_inline int try_hide_module(char *buf, int index, const char *chunk, int idx)
 {
     if (!cmp_module(chunk, idx))
         return 0;
     bpf_probe_write_user(buf + index, blank_spaces, module_name_lens[idx] - 1);
     return 1;
 }

 /*
  * Scan for configured module names to hide.
  *
  * Strategy: When we find a module name at start of line (after newline
  * or at position 0), we overwrite it with spaces. This effectively
  * "blanks" the module name while keeping the line structure intact.
  *
  * For a cleaner hide, we could scan for the entire line and replace
  * it with spaces, but that's more complex.
  */
 static long modules_scan_callback(u32 index, void *ctx)
 {
     struct scan_ctx *sc = ctx;

     if (index >= sc->len || index >= MAX_BUF_SIZE - MAX_MODULE_NAME_LEN)
         return 1;

     char chunk[MAX_MODULE_NAME_LEN];
     if (bpf_probe_read_user(chunk, MAX_MODULE_NAME_LEN, sc->buf + index) < 0)
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

     /* Manually-unrolled bounded loop over configured module names
      * (mirrors pidhide.bpf.c's check_pid_match() pattern) */
     if (num_modules_to_hide > 0 && try_hide_module(sc->buf, index, chunk, 0)) goto hidden;
     if (num_modules_to_hide > 1 && try_hide_module(sc->buf, index, chunk, 1)) goto hidden;
     if (num_modules_to_hide > 2 && try_hide_module(sc->buf, index, chunk, 2)) goto hidden;
     if (num_modules_to_hide > 3 && try_hide_module(sc->buf, index, chunk, 3)) goto hidden;
     if (num_modules_to_hide > 4 && try_hide_module(sc->buf, index, chunk, 4)) goto hidden;
     if (num_modules_to_hide > 5 && try_hide_module(sc->buf, index, chunk, 5)) goto hidden;
     if (num_modules_to_hide > 6 && try_hide_module(sc->buf, index, chunk, 6)) goto hidden;
     if (num_modules_to_hide > 7 && try_hide_module(sc->buf, index, chunk, 7)) goto hidden;

     return 0;

 hidden:
     sc->hidden_count++;
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
          log_bpf("[MODULES] hidden %d vbox modules", sc.hidden_count);
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