// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "devicetree_spoof.skel.h"

#define MAX_DT_VALUE_LEN 62

static struct env {
    char model[MAX_DT_VALUE_LEN + 1];
    char compatible[MAX_DT_VALUE_LEN + 1];
} env = {
    .model      = "Dell Inc. OptiPlex 7090",
    .compatible = "dell,optiplex-7090",
};

const char *argp_program_version = "devicetree_spoof 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"ARM64 Device Tree Spoofer\n"
"\n"
"Spoofs /proc/device-tree/model and /proc/device-tree/compatible for\n"
"ARM64 systems that boot via plain Device Tree (no UEFI/ACPI, so no\n"
"/sys/class/dmi/id) - e.g. Raspberry Pi or a bare QEMU 'virt' machine.\n"
"For UEFI-booted ARM64 VMs that DO have /sys/class/dmi/id, use dmi_spoof\n"
"instead.\n"
"\n"
"NOTE: real /proc/device-tree/compatible is a NUL-separated list of\n"
"compatible strings; this tool treats it as a single value (v1\n"
"simplification, documented limitation).\n"
"\n"
"USAGE: ./devicetree_spoof [--model NAME] [--compatible STRING]\n";

static const struct argp_option opts[] = {
    { "model",      'm', "NAME",   0, "Spoofed device-tree model (default: Dell Inc. OptiPlex 7090)" },
    { "compatible", 'c', "STRING", 0, "Spoofed device-tree compatible string (default: dell,optiplex-7090)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    char *dst = NULL;
    switch (key) {
    case 'm': dst = env.model;      break;
    case 'c': dst = env.compatible; break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    if (dst) {
        if (strlen(arg) > MAX_DT_VALUE_LEN) {
            fprintf(stderr, "Value too long (max %d chars): %s\n", MAX_DT_VALUE_LEN, arg);
            argp_usage(state);
        }
        strncpy(dst, arg, MAX_DT_VALUE_LEN);
        dst[MAX_DT_VALUE_LEN] = '\0';
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/* Copy value into a 64-byte rodata field, zero-padding the remainder so
 * the BPF side's fixed-width overwrite never leaves stale trailing bytes.
 * Unlike DMI's sysfs files, Device Tree strings are plain NUL-terminated
 * (no trailing newline convention), so no '\n' is appended here. */
static void set_fake_field(char *field, size_t field_size, const char *value)
{
    memset(field, 0, field_size);
    strncpy(field, value, field_size - 1);
}

int main(int argc, char **argv)
{
    struct devicetree_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = devicetree_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    set_fake_field(skel->rodata->fake_model, sizeof(skel->rodata->fake_model), env.model);
    set_fake_field(skel->rodata->fake_compatible, sizeof(skel->rodata->fake_compatible), env.compatible);

    err = devicetree_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = devicetree_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  ARM64 Device Tree Spoofer\n");
    printf("============================================\n\n");
    printf("Spoofing to: %s\n", env.model);
    printf("Compatible:  %s\n\n", env.compatible);
    printf("Target files:\n");
    printf("  /proc/device-tree/model\n");
    printf("  /proc/device-tree/compatible\n\n");
    printf("Test:\n");
    printf("  cat /proc/device-tree/model\n");
    printf("  cat /proc/device-tree/compatible\n\n");
    printf("Press Ctrl+C to stop...\n");

    while (!exiting) sleep(1);

cleanup:
    devicetree_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
