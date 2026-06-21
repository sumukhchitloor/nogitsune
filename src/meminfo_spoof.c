// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "meminfo_spoof.skel.h"

/* Field width matches the real kernel's own "%-16s%8lu %s\n" /proc/meminfo
 * format, so the configured line is always at least as long as the real
 * one for any value that fits the 8-digit field (up to ~95GB in kB). */
#define MAX_MEM_TOTAL_KB 99999999u

static struct env {
    unsigned int mem_total_kb;
} env = {
    .mem_total_kb = 16384000,
};

const char *argp_program_version = "meminfo_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"/proc/meminfo Spoofer\n"
"\n"
"Spoofs the MemTotal line in /proc/meminfo to a configurable value.\n"
"Defaults to 16384000 kB (~16GB) if no flags are given.\n"
"\n"
"USAGE: ./meminfo_spoof [--mem-total-kb N]\n";

static const struct argp_option opts[] = {
    { "mem-total-kb", 'm', "KB", 0, "Spoofed MemTotal value in kB (default: 16384000)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'm': {
        errno = 0;
        unsigned long val = strtoul(arg, NULL, 10);
        if (errno || val == 0 || val > MAX_MEM_TOTAL_KB) {
            fprintf(stderr, "Invalid --mem-total-kb value '%s': must be 1-%u\n",
                    arg, MAX_MEM_TOTAL_KB);
            argp_usage(state);
        }
        env.mem_total_kb = (unsigned int)val;
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
    struct meminfo_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = meminfo_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Build the replacement line and record its exact length - never
     * hardcode a byte count, that's what caused the original off-by-one. */
    int len = snprintf(skel->rodata->fake_memtotal_line,
                        sizeof(skel->rodata->fake_memtotal_line),
                        "%-16s%8u kB\n", "MemTotal:", env.mem_total_kb);
    if (len < 0 || (size_t)len >= sizeof(skel->rodata->fake_memtotal_line)) {
        fprintf(stderr, "Formatted MemTotal line too long\n");
        meminfo_spoof_bpf__destroy(skel);
        return 1;
    }
    skel->rodata->fake_memtotal_len = (unsigned int)len;

    err = meminfo_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = meminfo_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("[MEMINFO] Spoofer active (MemTotal -> %u kB)\n", env.mem_total_kb);

    while (!exiting) {
        sleep(1);
    }

cleanup:
    meminfo_spoof_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
