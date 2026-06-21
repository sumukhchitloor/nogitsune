// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "dmi_spoof.skel.h"

#define MAX_DMI_VALUE_LEN 30

static struct env {
    char sys_vendor[MAX_DMI_VALUE_LEN + 1];
    char product_name[MAX_DMI_VALUE_LEN + 1];
    char bios_vendor[MAX_DMI_VALUE_LEN + 1];
    char board_vendor[MAX_DMI_VALUE_LEN + 1];
    char chassis_vendor[MAX_DMI_VALUE_LEN + 1];
    char bios_version[MAX_DMI_VALUE_LEN + 1];
    char bios_date[MAX_DMI_VALUE_LEN + 1];
    char board_name[MAX_DMI_VALUE_LEN + 1];
    char product_family[MAX_DMI_VALUE_LEN + 1];
    char chassis_type[MAX_DMI_VALUE_LEN + 1];
    char product_version[MAX_DMI_VALUE_LEN + 1];
    char board_version[MAX_DMI_VALUE_LEN + 1];
} env = {
    .sys_vendor      = "Dell Inc.",
    .product_name    = "OptiPlex 7090",
    .bios_vendor     = "Dell Inc.",
    .board_vendor    = "Dell Inc.",
    .chassis_vendor  = "Dell Inc.",
    .bios_version    = "2.15.0",
    .bios_date       = "07/14/2023",
    .board_name      = "0K240Y",
    .product_family  = "OptiPlex",
    .chassis_type    = "3",
    .product_version = "1.0",
    .board_version   = "1.2",
};

const char *argp_program_version = "dmi_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"DMI/SMBIOS Spoofer\n"
"\n"
"Spoofs DMI/SMBIOS identity files under /sys/class/dmi/id (and the\n"
"/sys/devices/virtual/dmi/id alias) to a configurable hardware profile.\n"
"Defaults to a Dell OptiPlex 7090 profile if no flags are given.\n"
"\n"
"modalias/uevent substring rewriting (innotekGmbH/VirtualBox/Oracle/VBOX)\n"
"is not configurable - those are fixed-width embedded substring swaps.\n"
"\n"
"USAGE: ./dmi_spoof [--sys-vendor NAME] [--product-name NAME] ...\n";

enum {
    OPT_SYS_VENDOR = 1001,
    OPT_PRODUCT_NAME,
    OPT_BIOS_VENDOR,
    OPT_BOARD_VENDOR,
    OPT_CHASSIS_VENDOR,
    OPT_BIOS_VERSION,
    OPT_BIOS_DATE,
    OPT_BOARD_NAME,
    OPT_PRODUCT_FAMILY,
    OPT_CHASSIS_TYPE,
    OPT_PRODUCT_VERSION,
    OPT_BOARD_VERSION,
};

static const struct argp_option opts[] = {
    { "sys-vendor",      OPT_SYS_VENDOR,      "NAME",    0, "System vendor (default: Dell Inc.)" },
    { "product-name",    OPT_PRODUCT_NAME,    "NAME",    0, "Product name (default: OptiPlex 7090)" },
    { "bios-vendor",     OPT_BIOS_VENDOR,     "NAME",    0, "BIOS vendor (default: Dell Inc.)" },
    { "board-vendor",    OPT_BOARD_VENDOR,    "NAME",    0, "Board vendor (default: Dell Inc.)" },
    { "chassis-vendor",  OPT_CHASSIS_VENDOR,  "NAME",    0, "Chassis vendor (default: Dell Inc.)" },
    { "bios-version",    OPT_BIOS_VERSION,    "VERSION", 0, "BIOS version (default: 2.15.0)" },
    { "bios-date",       OPT_BIOS_DATE,       "DATE",    0, "BIOS date (default: 07/14/2023)" },
    { "board-name",      OPT_BOARD_NAME,      "NAME",    0, "Board name (default: 0K240Y)" },
    { "product-family",  OPT_PRODUCT_FAMILY,  "NAME",    0, "Product family (default: OptiPlex)" },
    { "chassis-type",    OPT_CHASSIS_TYPE,    "TYPE",    0, "Chassis type code (default: 3, desktop)" },
    { "product-version", OPT_PRODUCT_VERSION, "VERSION", 0, "Product version (default: 1.0)" },
    { "board-version",   OPT_BOARD_VERSION,   "VERSION", 0, "Board version (default: 1.2)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    char *dst = NULL;
    switch (key) {
    case OPT_SYS_VENDOR:      dst = env.sys_vendor;      break;
    case OPT_PRODUCT_NAME:    dst = env.product_name;    break;
    case OPT_BIOS_VENDOR:     dst = env.bios_vendor;     break;
    case OPT_BOARD_VENDOR:    dst = env.board_vendor;    break;
    case OPT_CHASSIS_VENDOR:  dst = env.chassis_vendor;  break;
    case OPT_BIOS_VERSION:    dst = env.bios_version;    break;
    case OPT_BIOS_DATE:       dst = env.bios_date;       break;
    case OPT_BOARD_NAME:      dst = env.board_name;      break;
    case OPT_PRODUCT_FAMILY:  dst = env.product_family;  break;
    case OPT_CHASSIS_TYPE:    dst = env.chassis_type;    break;
    case OPT_PRODUCT_VERSION: dst = env.product_version; break;
    case OPT_BOARD_VERSION:   dst = env.board_version;   break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    if (dst) {
        if (strlen(arg) > MAX_DMI_VALUE_LEN) {
            fprintf(stderr, "Value too long (max %d chars): %s\n", MAX_DMI_VALUE_LEN, arg);
            argp_usage(state);
        }
        strncpy(dst, arg, MAX_DMI_VALUE_LEN);
        dst[MAX_DMI_VALUE_LEN] = '\0';
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

/* Copy value+'\n' into a 32-byte rodata field, zero-padding the remainder so
 * the BPF side's fixed-width overwrite never leaves stale trailing bytes. */
static void set_fake_field(char *field, size_t field_size, const char *value)
{
    memset(field, 0, field_size);
    snprintf(field, field_size, "%s\n", value);
}

int main(int argc, char **argv)
{
    struct dmi_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = dmi_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        fprintf(stderr, "NOTE: Requires kernel 5.17+ for bpf_loop()\n");
        return 1;
    }

    set_fake_field(skel->rodata->fake0,  sizeof(skel->rodata->fake0),  env.sys_vendor);
    set_fake_field(skel->rodata->fake1,  sizeof(skel->rodata->fake1),  env.product_name);
    set_fake_field(skel->rodata->fake2,  sizeof(skel->rodata->fake2),  env.bios_vendor);
    set_fake_field(skel->rodata->fake3,  sizeof(skel->rodata->fake3),  env.board_vendor);
    set_fake_field(skel->rodata->fake4,  sizeof(skel->rodata->fake4),  env.chassis_vendor);
    set_fake_field(skel->rodata->fake5,  sizeof(skel->rodata->fake5),  env.bios_version);
    set_fake_field(skel->rodata->fake6,  sizeof(skel->rodata->fake6),  env.bios_date);
    set_fake_field(skel->rodata->fake7,  sizeof(skel->rodata->fake7),  env.board_name);
    set_fake_field(skel->rodata->fake8,  sizeof(skel->rodata->fake8),  env.product_family);
    set_fake_field(skel->rodata->fake9,  sizeof(skel->rodata->fake9),  env.chassis_type);
    set_fake_field(skel->rodata->fake10, sizeof(skel->rodata->fake10), env.product_version);
    set_fake_field(skel->rodata->fake11, sizeof(skel->rodata->fake11), env.board_version);

    err = dmi_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = dmi_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  DMI/SMBIOS Spoofer (14 files)\n");
    printf("============================================\n\n");
    printf("Spoofing to: %s %s\n\n", env.sys_vendor, env.product_name);
    printf("Simple files (direct replacement):\n");
    printf("  - sys_vendor, product_name, bios_vendor\n");
    printf("  - board_vendor, chassis_vendor, bios_version\n");
    printf("  - bios_date, board_name, product_family\n");
    printf("  - chassis_type, product_version, board_version\n\n");
    printf("Complex files (multi-pattern scan, not configurable):\n");
    printf("  - modalias  (replaces innotekGmbH, VirtualBox, OracleCorporation, VBOX)\n");
    printf("  - uevent    (replaces innotekGmbH, VirtualBox, OracleCorporation, VBOX)\n\n");
    printf("Press Ctrl+C to stop...\n");

    while (!exiting) sleep(1);

cleanup:
    dmi_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
