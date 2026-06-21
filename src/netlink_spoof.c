// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "netlink_spoof.skel.h"

#define IFNAMSIZ 16

static struct env {
    char iface[IFNAMSIZ];
    unsigned char mac[6];
} env = {
    .iface = "eth0",
    .mac = {0xa4, 0x5e, 0x60, 0x12, 0x34, 0x56}, /* Dell OUI */
};

const char *argp_program_version = "netlink_spoof 2.0 (configurable)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"Netlink MAC Address Spoofer\n"
"\n"
"Hooks recvmsg() and rewrites the MAC address reported for a target\n"
"interface inside RTM_NEWLINK netlink responses (e.g. from 'ip addr show').\n"
"\n"
"USAGE: ./netlink_spoof [--iface IFACE] [--mac xx:xx:xx:xx:xx:xx]\n";

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

int main(int argc, char **argv)
{
    struct netlink_spoof_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = netlink_spoof_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    strncpy(skel->rodata->target_iface, env.iface, sizeof(skel->rodata->target_iface) - 1);
    memcpy(skel->rodata->fake_mac, env.mac, sizeof(env.mac));

    err = netlink_spoof_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = netlink_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("Netlink MAC spoofing active!\n");
    printf("Hooking recvmsg() syscalls to spoof MAC for %s\n", env.iface);
    printf("Fake MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           env.mac[0], env.mac[1], env.mac[2], env.mac[3], env.mac[4], env.mac[5]);
    printf("Press Ctrl+C to stop.\n\n");
    printf("Test: ip addr show %s\n", env.iface);
    printf("Trace: sudo cat /sys/kernel/debug/tracing/trace_pipe\n\n");

    while (!exiting) {
        sleep(1);
    }

cleanup:
    netlink_spoof_bpf__destroy(skel);
    printf("\nStopped.\n");

    return err < 0 ? -err : 0;
}
