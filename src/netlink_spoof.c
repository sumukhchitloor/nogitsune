// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "netlink_spoof.skel.h"

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

int main(int argc, char **argv)
{
    struct netlink_spoof_bpf *skel;
    int err;

    /* Load and verify BPF application */
    skel = netlink_spoof_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Attach tracepoints */
    err = netlink_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Netlink MAC spoofing active!\n");
    printf("Hooking recvmsg() syscalls to spoof MAC for eth0\n");
    printf("Press Ctrl+C to stop.\n\n");
    printf("Test: ip addr show eth0\n");
    printf("Trace: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    /* Set up signal handler */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Wait */
    while (!exiting) {
        sleep(1);
    }

cleanup:
    netlink_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    
    return err < 0 ? -err : 0;
}