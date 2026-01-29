// SPDX-License-Identifier: BSD-3-Clause
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include "ioctl_spoof.skel.h"

// Event structure matching kernel side
struct event {
    unsigned int pid;
    char comm[16];
    char iface[16];
    unsigned char original_mac[6];
    unsigned char spoofed_mac[6];
    bool success;
};

static volatile bool exiting = false;

static void sig_handler(int sig)
{
    exiting = true;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    
    if (e->success) {
        printf("[✓] PID %d (%s) - Interface %s\n", e->pid, e->comm, e->iface);
        printf("    Original MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               e->original_mac[0], e->original_mac[1], e->original_mac[2],
               e->original_mac[3], e->original_mac[4], e->original_mac[5]);
        printf("    Spoofed MAC:  %02x:%02x:%02x:%02x:%02x:%02x\n",
               e->spoofed_mac[0], e->spoofed_mac[1], e->spoofed_mac[2],
               e->spoofed_mac[3], e->spoofed_mac[4], e->spoofed_mac[5]);
    } else {
        printf("[✗] PID %d (%s) - Failed to spoof MAC for %s\n", 
               e->pid, e->comm, e->iface);
    }
    
    return 0;
}

int main(int argc, char **argv)
{
    struct ioctl_spoof_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;
    
    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Open and load BPF application using skeleton
    skel = ioctl_spoof_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }
    
    // Attach BPF programs
    err = ioctl_spoof_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }
    
    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        err = -1;
        goto cleanup;
    }
    
    printf("=== ioctl MAC Address Spoofer ===\n");
    printf("Target interface: eth0\n");
    printf("Fake MAC: a4:5e:60:12:34:56 (Dell OUI)\n");
    printf("Press Ctrl+C to stop...\n\n");
    
    // Main event loop
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