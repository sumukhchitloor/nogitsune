// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "cpucount_spoof.skel.h"

#define MASK_BUF_SIZE 32
#define MAX_FAKE_CPU_COUNT (MASK_BUF_SIZE * 8) /* 256 */

static struct env {
    unsigned int fake_cpu_count;
} env = {
    .fake_cpu_count = 16,
};

const char *argp_program_version = "cpucount_spoof 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"CPU Affinity Mask Spoofer\n"
"\n"
"Spoofs the CPU mask sched_getaffinity() returns, inflating the apparent\n"
"CPU count for callers like `nproc` (which uses sched_getaffinity by\n"
"default, not /proc/cpuinfo). Defaults to 16 if no flags are given.\n"
"\n"
"NOTE: this covers sched_getaffinity only - /sys/devices/system/cpu/* and\n"
"/proc/cpuinfo's processor-line count (what `nproc --all` and ARM64 use)\n"
"are separate, unaddressed code paths.\n"
"\n"
"USAGE: ./cpucount_spoof [--fake-cpu-count N]\n";

static const struct argp_option opts[] = {
    { "fake-cpu-count", 'c', "N", 0, "Spoofed CPU count, 1-256 (default: 16)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'c': {
        errno = 0;
        unsigned long val = strtoul(arg, NULL, 10);
        if (errno || val == 0 || val > MAX_FAKE_CPU_COUNT) {
            fprintf(stderr, "Invalid --fake-cpu-count value '%s': must be 1-%d\n",
                    arg, MAX_FAKE_CPU_COUNT);
            argp_usage(state);
        }
        env.fake_cpu_count = (unsigned int)val;
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
    struct cpucount_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    long real_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    if (real_cpus > 0 && env.fake_cpu_count < (unsigned int)real_cpus) {
        fprintf(stderr,
                "[!] --fake-cpu-count %u is below the real online CPU count (%ld) - "
                "clamping up to %ld instead of making this look like FEWER CPUs\n",
                env.fake_cpu_count, real_cpus, real_cpus);
        env.fake_cpu_count = (unsigned int)real_cpus;
    }

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = cpucount_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Precompute the entire replacement mask in userspace: bits
     * [0, fake_cpu_count) set, rest zero - the BPF side just writes this
     * fixed buffer, no runtime-bounded loop needed there. */
    memset(skel->rodata->fake_affinity_mask, 0, MASK_BUF_SIZE);
    for (unsigned int i = 0; i < env.fake_cpu_count; i++) {
        skel->rodata->fake_affinity_mask[i / 8] |= (char)(1 << (i % 8));
    }

    err = cpucount_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = cpucount_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("[CPUCOUNT] Spoofer active (sched_getaffinity -> %u CPUs)\n", env.fake_cpu_count);
    printf("Test: nproc\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    cpucount_spoof_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}
