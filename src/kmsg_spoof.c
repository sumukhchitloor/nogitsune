// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "kmsg_spoof.skel.h"

const char *argp_program_version = "kmsg_spoof 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"Live Kernel-Log Sanitizer\n"
"\n"
"Blanks VBox/VirtualBox patterns from live /dev/kmsg reads and the legacy\n"
"syslog()/klogctl syscall. Patterns are fixed (not configurable - same\n"
"exact-byte-length-swap constraint as dmi_spoof's modalias scanner) - this\n"
"tool takes no options.\n"
"\n"
"LIMITATION: only sanitizes LIVE reads of the kernel ring buffer - does\n"
"NOT retroactively scrub boot messages systemd already archived into the\n"
"journal before this tool started. See docs/CONFIGURATION.md.\n"
"\n"
"USAGE: ./kmsg_spoof\n";

static const struct argp_option opts[] = { {} };

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

int main(int argc, char **argv)
{
    struct kmsg_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = kmsg_spoof_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        fprintf(stderr, "NOTE: Requires kernel 5.17+ for bpf_loop()\n");
        return 1;
    }

    err = kmsg_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  Kernel Log Sanitizer (live reads only)\n");
    printf("============================================\n\n");
    printf("Blanking patterns: VBox/vbox/VBOX, VirtualBox\n");
    printf("Hooking: /dev/kmsg reads, legacy syslog()/klogctl\n\n");
    printf("NOTE: does not scrub already-archived systemd journal entries\n");
    printf("from before this tool started - see --help\n\n");
    printf("Test:\n");
    printf("  dmesg | grep -i vbox\n\n");
    printf("Press Ctrl+C to stop...\n");

    while (!exiting) sleep(1);

cleanup:
    kmsg_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
