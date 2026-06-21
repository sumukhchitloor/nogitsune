// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "pci_spoof.skel.h"

#define MAX_PCI_MAPPINGS 8

struct pci_mapping {
    char from[7]; /* "0xXXXX" + NUL */
    char to[7];
};

static struct env {
    struct pci_mapping mappings[MAX_PCI_MAPPINGS];
    int num_mappings;
} env;

const char *argp_program_version = "pci_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"PCI Device ID Spoofer\n"
"\n"
"Spoofs PCI vendor/device IDs read from /sys/bus/pci/devices/*/vendor and\n"
"/sys/bus/pci/devices/*/device to configurable replacement values.\n"
"Defaults to VirtualBox -> Intel ID mappings if no flags are given.\n"
"\n"
"USAGE: ./pci_spoof [--vendor-map 0xFROM:0xTO ...]\n"
"EXAMPLE:\n"
"  ./pci_spoof --vendor-map 0x80ee:0x8086 --vendor-map 0xbeef:0x1234\n";

static const struct argp_option opts[] = {
    { "vendor-map", 'v', "FROM:TO", 0,
      "PCI ID mapping as 0xFROM:0xTO, e.g. 0x80ee:0x8086 (repeatable, max "
      "8 mappings; default: VirtualBox -> Intel IDs)" },
    {},
};

/* Normalizes a "0xXXXX" hex ID string into lowercase, validating format.
 * Returns 0 on success, -1 on invalid input. */
static int parse_hex_id(const char *s, char out[7])
{
    if (strlen(s) != 6 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X'))
        return -1;
    out[0] = '0';
    out[1] = 'x';
    for (int i = 2; i < 6; i++) {
        if (!isxdigit((unsigned char)s[i]))
            return -1;
        out[i] = (char)tolower((unsigned char)s[i]);
    }
    out[6] = '\0';
    return 0;
}

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'v': {
        if (env.num_mappings >= MAX_PCI_MAPPINGS) {
            fprintf(stderr, "Error: Maximum of %d PCI mappings supported\n", MAX_PCI_MAPPINGS);
            argp_usage(state);
        }
        char *colon = strchr(arg, ':');
        if (!colon) {
            fprintf(stderr, "Invalid --vendor-map '%s': expected FROM:TO\n", arg);
            argp_usage(state);
        }
        *colon = '\0';
        struct pci_mapping *m = &env.mappings[env.num_mappings];
        if (parse_hex_id(arg, m->from) || parse_hex_id(colon + 1, m->to)) {
            fprintf(stderr, "Invalid --vendor-map '%s:%s': each side must be "
                            "0x followed by 4 hex digits\n", arg, colon + 1);
            argp_usage(state);
        }
        env.num_mappings++;
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

/* Today's hardcoded VirtualBox -> Intel mappings, used only if the user
 * didn't supply any --vendor-map flags. */
static const struct pci_mapping default_mappings[] = {
    { "0x80ee", "0x8086" },
    { "0xbeef", "0x1234" },
    { "0xcafe", "0x5678" },
    { "0x0021", "0x1000" },
    { "0x0022", "0x1001" },
};

int main(int argc, char **argv)
{
    struct pci_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.num_mappings == 0) {
        env.num_mappings = sizeof(default_mappings) / sizeof(default_mappings[0]);
        memcpy(env.mappings, default_mappings, sizeof(default_mappings));
    }

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = pci_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->num_pci_mappings = env.num_mappings;
    for (int i = 0; i < env.num_mappings; i++) {
        memcpy(skel->rodata->pci_from[i], env.mappings[i].from, sizeof(env.mappings[i].from));
        snprintf(skel->rodata->pci_to[i], sizeof(skel->rodata->pci_to[i]), "%s\n", env.mappings[i].to);
    }

    err = pci_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = pci_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("PCI Device ID Spoofing Active\n");
    printf("==============================\n");
    printf("Target files: /sys/bus/pci/devices/*/vendor\n");
    printf("              /sys/bus/pci/devices/*/device\n");
    printf("\n");
    printf("Mappings:\n");
    for (int i = 0; i < env.num_mappings; i++) {
        printf("  %s -> %s\n", env.mappings[i].from, env.mappings[i].to);
    }
    printf("\n");
    printf("Press Ctrl+C to stop...\n");

    while (!exiting)
        sleep(1);

cleanup:
    pci_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
