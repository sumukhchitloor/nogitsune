// SPDX-License-Identifier: GPL-2.0
/*
 * dmi_spoof_full.bpf.c - Complete DMI/SMBIOS spoofing
 * 
 * Covers ALL DMI files including the tricky ones:
 * - Individual files (sys_vendor, product_name, etc.)
 * - modalias (combined string with all values)
 * - uevent (MODALIAS= line with all values)
 *
 * Uses bpf_loop() for modalias/uevent to replace multiple
 * VM-identifying strings in a single read.
 */

 #include "vmlinux.h"
 #include <bpf/bpf_helpers.h>
 #include <bpf/bpf_tracing.h>
 #include <bpf/bpf_core_read.h>
 
 char LICENSE[] SEC("license") = "GPL";
 
 #define MAX_BUF_SIZE 512
 
 /* ============ MAPS ============ */
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 8192);
     __type(key, u64);
     __type(value, int);
 } map_file_idx SEC(".maps");
 
 struct {
     __uint(type, BPF_MAP_TYPE_HASH);
     __uint(max_entries, 8192);
     __type(key, u64);
     __type(value, unsigned long);
 } map_buffs SEC(".maps");
 
 /* ============ FILE DEFINITIONS ============ */
 
 /* 
  * We match files by SUFFIX now, not full path.
  * This handles both /sys/class/dmi/id/ AND /sys/devices/virtual/dmi/id/
  *
  * File index mapping:
  *  0  = sys_vendor
  *  1  = product_name
  *  2  = bios_vendor
  *  3  = board_vendor
  *  4  = chassis_vendor
  *  5  = bios_version
  *  6  = bios_date
  *  7  = board_name
  *  8  = product_family
  *  9  = chassis_type
  *  10 = product_version
  *  11 = board_version
  *  12 = modalias (complex - multi-pattern)
  *  13 = uevent (complex - multi-pattern)
  */
 
 /* Fake values for simple files */
 const volatile char fake0[32]  = "Dell Inc.\n";
 const volatile char fake1[32]  = "OptiPlex 7090\n";
 const volatile char fake2[32]  = "Dell Inc.\n";
 const volatile char fake3[32]  = "Dell Inc.\n";
 const volatile char fake4[32]  = "Dell Inc.\n";
 const volatile char fake5[32]  = "2.15.0\n";
 const volatile char fake6[32]  = "07/14/2023\n";
 const volatile char fake7[32]  = "0K240Y\n";
 const volatile char fake8[32]  = "OptiPlex\n";
 const volatile char fake9[32]  = "3\n";           /* Desktop chassis */
 const volatile char fake10[32] = "1.0\n";
 const volatile char fake11[32] = "1.2\n";
 
 /* ============ HELPERS ============ */
 
 static __always_inline int str_eq(const char *a, const volatile char *b, int len) {
     for (int i = 0; i < len && i < 64; i++) {
         if (a[i] != b[i]) return 0;
         if (a[i] == '\0') return 1;
     }
     return 1;
 }
 
 /*
  * Check if filename ends with a specific suffix
  * This handles both:
  *   /sys/class/dmi/id/sys_vendor
  *   /sys/devices/virtual/dmi/id/sys_vendor
  */
 static __always_inline int str_ends_with(const char *path, const char *suffix, int suffix_len) {
     /* Find the end of path */
     int path_len = 0;
     for (int i = 0; i < 64; i++) {
         if (path[i] == '\0') {
             path_len = i;
             break;
         }
     }
     
     if (path_len < suffix_len)
         return 0;
     
     /* Compare suffix */
     int start = path_len - suffix_len;
     for (int i = 0; i < suffix_len; i++) {
         if (path[start + i] != suffix[i])
             return 0;
     }
     return 1;
 }
 
 /* Check if path contains "dmi/id/" - ensures we're in the right directory */
 static __always_inline int is_dmi_path(const char *path) {
     for (int i = 0; i < 50; i++) {
         if (path[i] == '\0') return 0;
         if (path[i] == 'd' && path[i+1] == 'm' && path[i+2] == 'i' &&
             path[i+3] == '/' && path[i+4] == 'i' && path[i+5] == 'd' &&
             path[i+6] == '/') {
             return 1;
         }
     }
     return 0;
 }
 
 static __always_inline int str_len(const volatile char *s) {
     int len = 0;
     for (int i = 0; i < 32; i++) {
         if (s[i] == '\0' || s[i] == '\n') return len + 1;
         len++;
     }
     return len;
 }
 
 /* ============ MODALIAS/UEVENT SCANNER ============ */
 
 /* 
  * These files contain strings like:
  * dmi:bvninnotekGmbH:bvrVirtualBox:bd12/01/2006:svninnotekGmbH:pnVirtualBox:...
  * 
  * We need to replace:
  * - "innotekGmbH" -> "DellInc____" (same length: 11 chars)
  * - "VirtualBox" -> "OptiPlex70" (same length: 10 chars)  
  * - "OracleCorporation" -> "DellIncorporat___" (same length: 17 chars)
  */
 
 struct scan_ctx {
     char *buf;
     int len;
     int count;
 };
 
 static long modalias_scan_callback(u32 index, void *ctx)
 {
     struct scan_ctx *sc = ctx;
     
     if (index >= sc->len || index >= MAX_BUF_SIZE - 20)
         return 1;
     
     char chunk[20];
     if (bpf_probe_read_user(chunk, 20, sc->buf + index) < 0)
         return 0;
     
     /* Pattern: "innotekGmbH" (11 chars) -> "DellInc...." */
     if (chunk[0] == 'i' && chunk[1] == 'n' && chunk[2] == 'n' &&
         chunk[3] == 'o' && chunk[4] == 't' && chunk[5] == 'e' &&
         chunk[6] == 'k' && chunk[7] == 'G' && chunk[8] == 'm' &&
         chunk[9] == 'b' && chunk[10] == 'H') {
         char repl[11] = "DellInc....";
         bpf_probe_write_user(sc->buf + index, repl, 11);
         sc->count++;
         return 0;
     }
     
     /* Pattern: "VirtualBox" (10 chars) -> "OptiPlex70" */
     if (chunk[0] == 'V' && chunk[1] == 'i' && chunk[2] == 'r' &&
         chunk[3] == 't' && chunk[4] == 'u' && chunk[5] == 'a' &&
         chunk[6] == 'l' && chunk[7] == 'B' && chunk[8] == 'o' &&
         chunk[9] == 'x') {
         char repl[10] = "OptiPlex70";
         bpf_probe_write_user(sc->buf + index, repl, 10);
         sc->count++;
         return 0;
     }
     
     /* Pattern: "OracleCorporation" (17 chars) -> "DellIncorporated." */
     if (chunk[0] == 'O' && chunk[1] == 'r' && chunk[2] == 'a' &&
         chunk[3] == 'c' && chunk[4] == 'l' && chunk[5] == 'e' &&
         chunk[6] == 'C' && chunk[7] == 'o' && chunk[8] == 'r' &&
         chunk[9] == 'p' && chunk[10] == 'o' && chunk[11] == 'r' &&
         chunk[12] == 'a' && chunk[13] == 't' && chunk[14] == 'i' &&
         chunk[15] == 'o' && chunk[16] == 'n') {
         char repl[17] = "DellIncorporated";
         bpf_probe_write_user(sc->buf + index, repl, 17);
         sc->count++;
         return 0;
     }
     
     /* Pattern: "VBOX" (4 chars) -> "DELL" - catches VBOX HARDDISK etc */
     if (chunk[0] == 'V' && chunk[1] == 'B' && chunk[2] == 'O' && chunk[3] == 'X') {
         char repl[4] = "DELL";
         bpf_probe_write_user(sc->buf + index, repl, 4);
         sc->count++;
         return 0;
     }
     
     return 0;
 }
 
 /* ============ TRACEPOINTS ============ */
 
 SEC("tp/syscalls/sys_enter_openat")
 int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
 {
     char filename[64];
     if (bpf_probe_read_user(filename, sizeof(filename), (void *)ctx->args[1]) < 0)
         return 0;
     
     /* First check if this is a DMI path at all */
     if (!is_dmi_path(filename))
         return 0;
     
     int file_idx = -1;
     
     /* Match by filename suffix - works for both:
      * /sys/class/dmi/id/sys_vendor
      * /sys/devices/virtual/dmi/id/sys_vendor
      */
     if (str_ends_with(filename, "sys_vendor", 10)) file_idx = 0;
     else if (str_ends_with(filename, "product_name", 12)) file_idx = 1;
     else if (str_ends_with(filename, "bios_vendor", 11)) file_idx = 2;
     else if (str_ends_with(filename, "board_vendor", 12)) file_idx = 3;
     else if (str_ends_with(filename, "chassis_vendor", 14)) file_idx = 4;
     else if (str_ends_with(filename, "bios_version", 12)) file_idx = 5;
     else if (str_ends_with(filename, "bios_date", 9)) file_idx = 6;
     else if (str_ends_with(filename, "board_name", 10)) file_idx = 7;
     else if (str_ends_with(filename, "product_family", 14)) file_idx = 8;
     else if (str_ends_with(filename, "chassis_type", 12)) file_idx = 9;
     else if (str_ends_with(filename, "product_version", 15)) file_idx = 10;
     else if (str_ends_with(filename, "board_version", 13)) file_idx = 11;
     else if (str_ends_with(filename, "modalias", 8)) file_idx = 12;
     else if (str_ends_with(filename, "uevent", 6)) file_idx = 13;
     
     if (file_idx >= 0) {
         u64 pid_tgid = bpf_get_current_pid_tgid();
         bpf_map_update_elem(&map_file_idx, &pid_tgid, &file_idx, BPF_ANY);
     }
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_enter_read")
 int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
 {
     u64 pid_tgid = bpf_get_current_pid_tgid();
     
     if (!bpf_map_lookup_elem(&map_file_idx, &pid_tgid))
         return 0;
     
     unsigned long buf = ctx->args[1];
     if (buf)
         bpf_map_update_elem(&map_buffs, &pid_tgid, &buf, BPF_ANY);
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_exit_read")
 int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
 {
     u64 pid_tgid = bpf_get_current_pid_tgid();
     
     int *pfile_idx = bpf_map_lookup_elem(&map_file_idx, &pid_tgid);
     if (!pfile_idx)
         return 0;
     
     unsigned long *pbuf = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
     if (!pbuf)
         return 0;
     
     long ret = ctx->ret;
     if (ret <= 0)
         return 0;
     
     int file_idx = *pfile_idx;
     char *buf = (char *)*pbuf;
     
     /* Simple file replacements (0-11) */
     switch (file_idx) {
         case 0:  bpf_probe_write_user(buf, (void *)fake0, str_len(fake0)); break;
         case 1:  bpf_probe_write_user(buf, (void *)fake1, str_len(fake1)); break;
         case 2:  bpf_probe_write_user(buf, (void *)fake2, str_len(fake2)); break;
         case 3:  bpf_probe_write_user(buf, (void *)fake3, str_len(fake3)); break;
         case 4:  bpf_probe_write_user(buf, (void *)fake4, str_len(fake4)); break;
         case 5:  bpf_probe_write_user(buf, (void *)fake5, str_len(fake5)); break;
         case 6:  bpf_probe_write_user(buf, (void *)fake6, str_len(fake6)); break;
         case 7:  bpf_probe_write_user(buf, (void *)fake7, str_len(fake7)); break;
         case 8:  bpf_probe_write_user(buf, (void *)fake8, str_len(fake8)); break;
         case 9:  bpf_probe_write_user(buf, (void *)fake9, str_len(fake9)); break;
         case 10: bpf_probe_write_user(buf, (void *)fake10, str_len(fake10)); break;
         case 11: bpf_probe_write_user(buf, (void *)fake11, str_len(fake11)); break;
         
         /* modalias and uevent - need multi-pattern scan */
         case 12:
         case 13: {
             int len = ret;
             if (len > MAX_BUF_SIZE)
                 len = MAX_BUF_SIZE;
             
             struct scan_ctx sc = {
                 .buf = buf,
                 .len = len,
                 .count = 0,
             };
             
             bpf_loop(len, modalias_scan_callback, &sc, 0);
             
             if (sc.count > 0) {
                 bpf_printk("[DMI] modalias/uevent: replaced %d patterns", sc.count);
             }
             break;
         }
     }
     
     return 0;
 }
 
 SEC("tp/syscalls/sys_enter_close")
 int handle_close(struct trace_event_raw_sys_enter *ctx)
 {
     u64 pid_tgid = bpf_get_current_pid_tgid();
     bpf_map_delete_elem(&map_file_idx, &pid_tgid);
     bpf_map_delete_elem(&map_buffs, &pid_tgid);
     return 0;
 }