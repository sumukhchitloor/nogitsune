// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "common_um.h"
#include "ioctl_spoof.skel.h"

#define IFNAMSIZ 16

// Event structure matching kernel side
struct event {
    unsigned int pid;
    char comm[16];
    char iface[16];
    unsigned char original_mac[6];
    unsigned char spoofed_mac[6];
    bool success;
};

static struct env {
    char iface[IFNAMSIZ];
    unsigned char mac[6];
} env = {
    .iface = "eth0",
    .mac = {0xa4, 0x5e, 0x60, 0x12, 0x34, 0x56}, /* Dell OUI */
};

const char *argp_program_version = "ioctl_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"ioctl MAC Address Spoofer\n"
"\n"
"Hooks SIOCGIFHWADDR ioctl calls and rewrites the returned MAC address\n"
"for a target network interface.\n"
"\n"
"USAGE: ./ioctl_spoof [--iface IFACE] [--mac xx:xx:xx:xx:xx:xx]\n";

static const struct argp_option opts[] = {
    { "iface", 'i', "IFACE", 0, "Target interface to spoof (default: eth0)" },
    { "mac",   'm', "MAC",   0, "Fake MAC address, format xx:xx:xx:xx:xx:xx (default: Dell OUI a4:5e:60:12:34:56)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        if (strlen(arg) >= IFNAMSIZ) {
            fprintf(stderr, "Interface name too long (max %d chars): %s\n", IFNAMSIZ - 1, arg);
            argp_usage(state);
        }
        strncpy(env.iface, arg, sizeof(env.iface) - 1);
        env.iface[sizeof(env.iface) - 1] = '\0';
        break;
    case 'm': {
        unsigned int b[6];
        if (sscanf(arg, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
            fprintf(stderr, "Invalid --mac value '%s': expected xx:xx:xx:xx:xx:xx\n", arg);
            argp_usage(state);
        }
        for (int i = 0; i < 6; i++) {
            if (b[i] > 0xff) {
                fprintf(stderr, "Invalid --mac value '%s': byte out of range\n", arg);
                argp_usage(state);
            }
            env.mac[i] = (unsigned char)b[i];
        }
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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;

    if (e->success) {
        printf("[+] PID %d (%s) - Interface %s\n", e->pid, e->comm, e->iface);
        printf("    Original MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               e->original_mac[0], e->original_mac[1], e->original_mac[2],
               e->original_mac[3], e->original_mac[4], e->original_mac[5]);
        printf("    Spoofed MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
               e->spoofed_mac[0], e->spoofed_mac[1], e->spoofed_mac[2],
               e->spoofed_mac[3], e->spoofed_mac[4], e->spoofed_mac[5]);
    } else {
        printf("[-] PID %d (%s) - Failed to spoof MAC for %s\n",
               e->pid, e->comm, e->iface);
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct ioctl_spoof_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = ioctl_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    strncpy(skel->rodata->target_iface, env.iface, sizeof(skel->rodata->target_iface) - 1);
    memcpy(skel->rodata->fake_mac, env.mac, sizeof(env.mac));

    err = ioctl_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = ioctl_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }

    printf("=== ioctl MAC Address Spoofer ===\n");
    printf("Target interface: %s\n", env.iface);
    printf("Fake MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           env.mac[0], env.mac[1], env.mac[2], env.mac[3], env.mac[4], env.mac[5]);
    printf("Press Ctrl+C to stop...\n\n");

    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }

cleanup:
    printf("\nCleaning up...\n");
    ring_buffer__free(rb);
    ioctl_spoof_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
