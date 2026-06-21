// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "modules_hide.skel.h"

#define MAX_MODULES_TO_HIDE 8
#define MAX_MODULE_NAME_LEN 32

static struct env {
    char modules[MAX_MODULES_TO_HIDE][MAX_MODULE_NAME_LEN];
    int num_modules;
} env;

const char *argp_program_version = "modules_hide 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"Kernel Module Hider (/proc/modules)\n"
"\n"
"Hides configured kernel module names from /proc/modules by blanking\n"
"them with spaces when read. Defaults to hiding vboxguest, vboxsf, and\n"
"vboxvideo if no flags are given.\n"
"\n"
"USAGE: ./modules_hide [--module NAME ...]\n"
"EXAMPLE:\n"
"  ./modules_hide --module vboxguest --module vboxsf\n";

static const struct argp_option opts[] = {
    { "module", 'm', "NAME", 0,
      "Kernel module name to hide (repeatable, max 8; default: vboxguest, vboxsf, vboxvideo)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'm':
        if (env.num_modules >= MAX_MODULES_TO_HIDE) {
            fprintf(stderr, "Error: Maximum of %d modules supported\n", MAX_MODULES_TO_HIDE);
            argp_usage(state);
        }
        /* Reserve 1 byte for the trailing space marker the BPF side adds */
        if (strlen(arg) >= MAX_MODULE_NAME_LEN - 1) {
            fprintf(stderr, "Module name too long (max %d chars): %s\n", MAX_MODULE_NAME_LEN - 2, arg);
            argp_usage(state);
        }
        strncpy(env.modules[env.num_modules], arg, MAX_MODULE_NAME_LEN - 1);
        env.num_modules++;
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

static const char *default_modules[] = { "vboxguest", "vboxsf", "vboxvideo" };

int main(int argc, char **argv)
{
    struct modules_hide_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.num_modules == 0) {
        env.num_modules = sizeof(default_modules) / sizeof(default_modules[0]);
        for (int i = 0; i < env.num_modules; i++) {
            strncpy(env.modules[i], default_modules[i], MAX_MODULE_NAME_LEN - 1);
        }
    }

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = modules_hide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        fprintf(stderr, "NOTE: Requires kernel 5.17+ for bpf_loop()\n");
        return 1;
    }

    skel->rodata->num_modules_to_hide = env.num_modules;
    for (int i = 0; i < env.num_modules; i++) {
        /* Pattern stored as "<name> " (name + trailing space separator
         * from /proc/modules' "name size used_by ..." format) */
        int len = snprintf(skel->rodata->modules_to_hide[i],
                            sizeof(skel->rodata->modules_to_hide[i]),
                            "%s ", env.modules[i]);
        skel->rodata->module_name_lens[i] = len;
    }

    err = modules_hide_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
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
    for (int i = 0; i < env.num_modules; i++) {
        printf("  - %s\n", env.modules[i]);
    }
    printf("\nTest:\n");
    printf("  lsmod | grep <name>    # Should show nothing\n");
    printf("  cat /proc/modules | grep <name>\n\n");
    printf("Press Ctrl+C to stop...\n");

    while (!exiting) sleep(1);

cleanup:
    modules_hide_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
