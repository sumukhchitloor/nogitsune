// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "common_um.h"
#include "fshide.skel.h"

#define MAX_HIDDEN_NAMES 16
#define MAX_NAME_LEN 32

static struct env {
    char names[MAX_HIDDEN_NAMES][MAX_NAME_LEN];
    int num_names;
} env;

const char *argp_program_version = "fshide 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"Filesystem Entry Hider\n"
"\n"
"Hides directory entries whose name starts with a configured prefix from\n"
"any directory listing (ls/find/readdir) system-wide, by hooking\n"
"getdents64 - the same d_reclen-splice technique pidhide.bpf.c uses for\n"
"/proc PID entries, generalized to arbitrary filenames in any directory.\n"
"\n"
"This only defeats enumeration. A caller that already knows the exact\n"
"path can still open/stat it directly - see pathdeny for that gap.\n"
"\n"
"Defaults to hiding common VirtualBox Guest Additions artifacts if no\n"
"flags are given.\n"
"\n"
"USAGE: ./fshide [--name PREFIX ...]\n"
"EXAMPLE:\n"
"  ./fshide --name VBoxGuestAdditions --name vboxadd\n";

static const struct argp_option opts[] = {
    { "name", 'n', "PREFIX", 0,
      "Filename prefix to hide from directory listings (repeatable, max 16; "
      "default: common VirtualBox Guest Additions artifact names)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'n':
        if (env.num_names >= MAX_HIDDEN_NAMES) {
            fprintf(stderr, "Error: Maximum of %d names supported\n", MAX_HIDDEN_NAMES);
            argp_usage(state);
        }
        if (strlen(arg) >= MAX_NAME_LEN) {
            fprintf(stderr, "Name too long (max %d chars): %s\n", MAX_NAME_LEN - 1, arg);
            argp_usage(state);
        }
        strncpy(env.names[env.num_names], arg, MAX_NAME_LEN - 1);
        env.num_names++;
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

/* Confirmed-present VirtualBox Guest Additions artifacts on a real install -
 * directories, kernel modules, and binaries that show up across /opt,
 * /usr/sbin, /usr/bin, and kernel module directory listings. */
static const char *default_names[] = {
    "VBoxGuestAdditions", "vboxadd", "vboxguest.ko", "vboxsf.ko",
    "vboxvideo.ko", "vboxguest", "mount.vboxsf", "VBoxService",
    "VBoxClient", "VBoxControl", "VBoxDRMClient",
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hid entry from program %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to hide entry from program %d (%s)\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct fshide_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.num_names == 0) {
        env.num_names = sizeof(default_names) / sizeof(default_names[0]);
        for (int i = 0; i < env.num_names; i++) {
            strncpy(env.names[i], default_names[i], MAX_NAME_LEN - 1);
        }
    }

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = fshide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->rodata->num_hidden_names = env.num_names;
    for (int i = 0; i < env.num_names; i++) {
        strncpy(skel->rodata->hidden_names[i], env.names[i], MAX_NAME_LEN - 1);
        skel->rodata->name_lens[i] = (int)strlen(env.names[i]);
    }

    err = fshide_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    int ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index, &prog_fd, BPF_ANY);
    if (ret == -1) {
        fprintf(stderr, "Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map_update_elem(
        bpf_map__fd(skel->maps.map_prog_array),
        &index, &prog_fd, BPF_ANY);
    if (ret == -1) {
        fprintf(stderr, "Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    err = fshide_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("============================================\n");
    printf("  Filesystem Entry Hider\n");
    printf("============================================\n\n");
    printf("Hiding names (prefix match):\n");
    for (int i = 0; i < env.num_names; i++) {
        printf("  - %s\n", env.names[i]);
    }
    printf("\nPress Ctrl+C to stop...\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    fshide_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : 0;
}
