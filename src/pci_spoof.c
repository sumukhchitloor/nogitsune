// PCI Device Spoofing - VirtualBox to Intel
// Userland loader in C
//
// VirtualBox PCI signatures:
//   Vendor: 0x80ee (VirtualBox)
//   Devices: 0xbeef, 0xcafe, 0x0021, 0x0022
//
// Spoofed to Intel:
//   Vendor: 0x8086 (Intel Corporation)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

static volatile sig_atomic_t keep_running = 1;

static void sig_handler(int sig) {
    keep_running = 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog_enter = NULL;
    struct bpf_program *prog_exit = NULL;
    struct bpf_link *link_enter = NULL;
    struct bpf_link *link_exit = NULL;
    int err;

    // Set up signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    // Set up libbpf errors and debug info callback
    libbpf_set_print(libbpf_print_fn);

    // Open BPF object file
    obj = bpf_object__open_file(".output/pci_spoof.bpf.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: failed to open BPF object file\n");
        return 1;
    }

    // Load BPF object into kernel
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "ERROR: failed to load BPF object: %d\n", err);
        goto cleanup;
    }

    // Find the BPF programs
    struct bpf_program *prog_openat = bpf_object__find_program_by_name(obj, "handle_openat");
    if (!prog_openat) {
        fprintf(stderr, "ERROR: failed to find handle_openat program\n");
        err = -1;
        goto cleanup;
    }

    prog_enter = bpf_object__find_program_by_name(obj, "handle_read_enter");
    if (!prog_enter) {
        fprintf(stderr, "ERROR: failed to find handle_read_enter program\n");
        err = -1;
        goto cleanup;
    }

    prog_exit = bpf_object__find_program_by_name(obj, "handle_read_exit");
    if (!prog_exit) {
        fprintf(stderr, "ERROR: failed to find handle_read_exit program\n");
        err = -1;
        goto cleanup;
    }

    // Attach to tracepoints
    struct bpf_link *link_openat = bpf_program__attach(prog_openat);
    if (libbpf_get_error(link_openat)) {
        fprintf(stderr, "ERROR: failed to attach sys_enter_openat tracepoint\n");
        link_openat = NULL;
        err = -1;
        goto cleanup;
    }

    link_enter = bpf_program__attach(prog_enter);
    if (libbpf_get_error(link_enter)) {
        fprintf(stderr, "ERROR: failed to attach sys_enter_read tracepoint\n");
        link_enter = NULL;
        err = -1;
        goto cleanup;
    }

    link_exit = bpf_program__attach(prog_exit);
    if (libbpf_get_error(link_exit)) {
        fprintf(stderr, "ERROR: failed to attach sys_exit_read tracepoint\n");
        link_exit = NULL;
        err = -1;
        goto cleanup;
    }

    printf("PCI Device ID Spoofing Active\n");
    printf("==============================\n");
    printf("Spoofing VirtualBox PCI IDs -> Intel IDs\n");
    printf("\n");
    printf("Target files: /sys/bus/pci/devices/*/vendor\n");
    printf("              /sys/bus/pci/devices/*/device\n");
    printf("\n");
    printf("Mappings:\n");
    printf("  0x80ee -> 0x8086 (VirtualBox vendor -> Intel)\n");
    printf("  0xbeef -> 0x1234 (VirtualBox device -> Intel device)\n");
    printf("  0xcafe -> 0x5678 (VirtualBox device -> Intel device)\n");
    printf("  0x0021 -> 0x1000 (VirtualBox device -> Intel device)\n");
    printf("  0x0022 -> 0x1001 (VirtualBox device -> Intel device)\n");
    printf("\n");
    printf("Press Ctrl-C to exit\n");
    printf("\n");

    // Keep running until interrupted
    while (keep_running) {
        sleep(1);
    }

    printf("\nStopping PCI spoofing...\n");

cleanup:
    bpf_link__destroy(link_openat);
    bpf_link__destroy(link_enter);
    bpf_link__destroy(link_exit);
    bpf_object__close(obj);

    return err != 0;
}