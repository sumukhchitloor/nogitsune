// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "cpuinfo_spoof.skel.h"

static volatile int running = 1;

static void sig_handler(int sig) {
    running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG)
        return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct cpuinfo_spoof_bpf *skel;
    int err;
    
    libbpf_set_print(libbpf_print_fn);
    
    /* Increase resource limits */
    struct rlimit rlim = { RLIM_INFINITY, RLIM_INFINITY };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
        fprintf(stderr, "Warning: Failed to increase RLIMIT_MEMLOCK\n");
    }
    
    /* Open BPF skeleton */
    skel = cpuinfo_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    
    /* Load BPF programs */
    err = cpuinfo_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        fprintf(stderr, "\nNOTE: This program requires Linux kernel 5.17+ for bpf_loop() support.\n");
        fprintf(stderr, "Check your kernel version: uname -r\n");
        goto cleanup;
    }
    
    /* Attach BPF programs */
    err = cpuinfo_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    printf("==============================================\n");
    printf("  /proc/cpuinfo Multi-Occurrence Spoofer\n");
    printf("  (using bpf_loop for unlimited scanning)\n");
    printf("==============================================\n\n");
    printf("[+] Loaded and attached successfully!\n\n");
    printf("Spoofing ALL occurrences across ALL CPUs:\n");
    printf("  * 'hypervisor ' -> removed (spaces)\n");
    printf("  * cpu cores    -> 8\n");
    printf("  * siblings     -> 8\n");
    printf("  * microcode 0xffffffff -> 0x000000b4\n\n");
    printf("Test commands:\n");
    printf("  cat /proc/cpuinfo | grep -c hypervisor  # Should be 0\n");
    printf("  cat /proc/cpuinfo | grep 'cpu cores'    # All should show 8\n");
    printf("  cat /proc/cpuinfo | grep siblings       # All should show 8\n");
    printf("  cat /proc/cpuinfo | grep microcode      # All should show 0x000000b4\n\n");
    printf("Watch trace output:\n");
    printf("  sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");
    printf("Press Ctrl+C to stop...\n\n");
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    while (running)
        sleep(1);
    
    printf("\n[*] Stopping...\n");

cleanup:
    cpuinfo_spoof_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}