// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "modules_hide.skel.h"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv)
{
    struct modules_hide_bpf *skel;
    int err;

    skel = modules_hide_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        fprintf(stderr, "NOTE: Requires kernel 5.17+ for bpf_loop()\n");
        return 1;
    }

    err = modules_hide_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  Kernel Module Hider (/proc/modules)\n");
    printf("============================================\n\n");
    printf("Hiding modules:\n");
    printf("  - vboxguest\n");
    printf("  - vboxsf\n");
    printf("  - vboxvideo\n\n");
    printf("Test:\n");
    printf("  lsmod | grep vbox    # Should show nothing or #hidden\n");
    printf("  cat /proc/modules | grep vbox\n\n");
    printf("Press Ctrl+C to stop...\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) sleep(1);

cleanup:
    modules_hide_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}