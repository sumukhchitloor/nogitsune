// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "uptime_spoof.skel.h"

/* Sane upper bound - real /proc/uptime values are bounded by how long the
 * machine has actually been up; this just guards against a typo creating
 * an absurd value, not a hard kernel limit. */
#define MAX_UPTIME_SECONDS 3153600000u /* ~100 years */

static struct env {
    unsigned int uptime_seconds;
} env = {
    .uptime_seconds = 259200, /* 3 days */
};

const char *argp_program_version = "uptime_spoof 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"/proc/uptime Spoofer\n"
"\n"
"Spoofs /proc/uptime to a configurable large value, defeating the\n"
"\"suspiciously fresh boot\" heuristic some sandboxes/malware check for.\n"
"Defaults to 259200 seconds (3 days) if no flags are given.\n"
"\n"
"NOTE: this is a static value, not a ticking clock - reading it twice\n"
"with a real delay between reads returns the same frozen number both\n"
"times, which is itself a (less common) tell.\n"
"\n"
"USAGE: ./uptime_spoof [--uptime-seconds N]\n";

static const struct argp_option opts[] = {
    { "uptime-seconds", 'u', "SECONDS", 0, "Spoofed uptime value in seconds (default: 259200, 3 days)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'u': {
        errno = 0;
        unsigned long val = strtoul(arg, NULL, 10);
        if (errno || val == 0 || val > MAX_UPTIME_SECONDS) {
            fprintf(stderr, "Invalid --uptime-seconds value '%s': must be 1-%u\n",
                    arg, MAX_UPTIME_SECONDS);
            argp_usage(state);
        }
        env.uptime_seconds = (unsigned int)val;
        break;
    }
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
    struct uptime_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = uptime_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Build the replacement line and record its exact length - never
     * hardcode a byte count (the meminfo off-by-one lesson). Idle time
     * just mirrors uptime - this is a "good enough" spoof, not aiming for
     * perfect realism. */
    int len = snprintf(skel->rodata->fake_uptime_line,
                        sizeof(skel->rodata->fake_uptime_line),
                        "%u.00 %u.00\n", env.uptime_seconds, env.uptime_seconds);
    if (len < 0 || (size_t)len >= sizeof(skel->rodata->fake_uptime_line)) {
        fprintf(stderr, "Formatted uptime line too long\n");
        uptime_spoof_bpf__destroy(skel);
        return 1;
    }
    skel->rodata->fake_uptime_len = (unsigned int)len;

    err = uptime_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = uptime_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("[UPTIME] Spoofer active (uptime -> %u seconds)\n", env.uptime_seconds);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    uptime_spoof_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
