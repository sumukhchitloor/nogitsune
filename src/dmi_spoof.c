// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "dmi_spoof.skel.h"

static volatile bool exiting = false;
static void sig_handler(int sig) { exiting = true; }

int main(int argc, char **argv)
{
    struct dmi_spoof_bpf *skel;
    int err;

    skel = dmi_spoof_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        fprintf(stderr, "NOTE: Requires kernel 5.17+ for bpf_loop()\n");
        return 1;
    }

    err = dmi_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  DMI/SMBIOS Full Spoofer (14 files)\n");
    printf("============================================\n\n");
    printf("Spoofing to: Dell OptiPlex 7090\n\n");
    printf("Simple files (direct replacement):\n");
    printf("  - sys_vendor, product_name, bios_vendor\n");
    printf("  - board_vendor, chassis_vendor, bios_version\n");
    printf("  - bios_date, board_name, product_family\n");
    printf("  - chassis_type, product_version, board_version\n\n");
    printf("Complex files (multi-pattern scan):\n");
    printf("  - modalias  (replaces innotekGmbH, VirtualBox, OracleCorporation)\n");
    printf("  - uevent    (replaces innotekGmbH, VirtualBox, OracleCorporation)\n\n");
    printf("Test:\n");
    printf("  cat /sys/class/dmi/id/modalias\n");
    printf("  cat /sys/class/dmi/id/uevent\n\n");
    printf("Press Ctrl+C to stop...\n");

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (!exiting) sleep(1);

cleanup:
    dmi_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}