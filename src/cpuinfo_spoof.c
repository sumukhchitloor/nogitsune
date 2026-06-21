// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <ctype.h>
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

static struct env {
    char cores;
    char microcode[11];
    int keep_hypervisor_flag;
} env = {
    .cores = '8',
    .microcode = "0x000000b4",
    .keep_hypervisor_flag = 0,
};

const char *argp_program_version = "cpuinfo_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"/proc/cpuinfo Multi-Occurrence Spoofer\n"
"\n"
"Uses bpf_loop() to scan and rewrite every occurrence of VM-identifying\n"
"fields in /proc/cpuinfo across all CPUs in a single read.\n"
"\n"
"NOTE: ARM64 /proc/cpuinfo has no 'hypervisor' flag line and a different\n"
"format entirely - this tool is x86-specific and is a safe no-op there.\n"
"\n"
"USAGE: ./cpuinfo_spoof [--cores N] [--microcode 0xHEXHEXHEXHEX] [--keep-hypervisor-flag]\n";

static const struct argp_option opts[] = {
    { "cores",                 'c', "1-9",  0, "Replacement digit for cpu cores/siblings counts (default: 8)" },
    { "microcode",             'm', "HEX",  0, "Replacement microcode signature, format 0xXXXXXXXX (default: 0x000000b4)" },
    { "keep-hypervisor-flag",  'k', NULL,   0, "Don't blank out the 'hypervisor' flag (default: strip it)" },
    {},
};

static int is_valid_microcode(const char *s)
{
    if (strlen(s) != 10 || s[0] != '0' || s[1] != 'x')
        return 0;
    for (int i = 2; i < 10; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return 0;
    }
    return 1;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'c':
        if (strlen(arg) != 1 || arg[0] < '1' || arg[0] > '9') {
            fprintf(stderr, "Invalid --cores value '%s': must be a single digit 1-9 "
                            "(the BPF side only ever overwrites 1 byte)\n", arg);
            argp_usage(state);
        }
        env.cores = arg[0];
        break;
    case 'm':
        if (!is_valid_microcode(arg)) {
            fprintf(stderr, "Invalid --microcode value '%s': must be exactly "
                            "0x followed by 8 hex digits\n", arg);
            argp_usage(state);
        }
        strncpy(env.microcode, arg, sizeof(env.microcode) - 1);
        env.microcode[sizeof(env.microcode) - 1] = '\0';
        break;
    case 'k':
        env.keep_hypervisor_flag = 1;
        break;
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
    struct cpuinfo_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

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

    skel->rodata->target_cores = env.cores;
    skel->rodata->strip_hypervisor = !env.keep_hypervisor_flag;
    strncpy(skel->rodata->target_microcode, env.microcode, sizeof(skel->rodata->target_microcode) - 1);
    skel->rodata->target_microcode[sizeof(skel->rodata->target_microcode) - 1] = '\0';

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
    if (!env.keep_hypervisor_flag)
        printf("  * 'hypervisor ' -> removed (spaces)\n");
    else
        printf("  * 'hypervisor ' -> left as-is (--keep-hypervisor-flag)\n");
    printf("  * cpu cores    -> %c\n", env.cores);
    printf("  * siblings     -> %c\n", env.cores);
    printf("  * microcode 0xffffffff -> %s\n\n", env.microcode);
    printf("Test commands:\n");
    printf("  cat /proc/cpuinfo | grep -c hypervisor\n");
    printf("  cat /proc/cpuinfo | grep 'cpu cores'\n");
    printf("  cat /proc/cpuinfo | grep siblings\n");
    printf("  cat /proc/cpuinfo | grep microcode\n\n");
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
