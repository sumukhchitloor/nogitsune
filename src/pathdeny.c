// SPDX-License-Identifier: GPL-2.0
#include <argp.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include "common_um.h"
#include "pathdeny.skel.h"

/* CLI still accepts at most 8 --path args (matches nogitsune.c's profile
 * cap), but the BPF side's array is 16 (see pathdeny.bpf.c) - main() below
 * expands each configured path that's a symlink into two entries (the
 * symlink itself + its resolved real target), so 8 configured paths need
 * room for up to 16 total. */
#define MAX_CLI_PATHS 8
#define MAX_HIDDEN_PATHS 16
#define MAX_PATH_LEN 80

static struct env {
    char paths[MAX_CLI_PATHS][MAX_PATH_LEN];
    int num_paths;
} env;

const char *argp_program_version = "pathdeny 1.0";
const char *argp_program_bug_address = "<sumukhchitloor18@gmail.com>";
const char argp_program_doc[] =
"Exact-Path Hider (BPF LSM)\n"
"\n"
"Denies open()/stat()/access() on configured exact paths, returning ENOENT\n"
"as if they don't exist - defeats direct probing of a known path, which\n"
"fshide's directory-listing hiding can't (a caller that already knows the\n"
"exact path doesn't need to enumerate the directory).\n"
"\n"
"Needs BPF LSM support (CONFIG_BPF_LSM + 'bpf' active in\n"
"/sys/kernel/security/lsm). If unavailable, this tool exits cleanly\n"
"without affecting any other spoofer.\n"
"\n"
"LIMITATION: access() coverage only applies to paths that already existed\n"
"when this tool started (it resolves each path's (device, inode) once at\n"
"startup) - unlike open()/stat() coverage, which matches by path string\n"
"dynamically regardless of when the path appeared.\n"
"\n"
"USAGE: ./pathdeny --path /exact/path [--path ...]\n"
"EXAMPLE:\n"
"  ./pathdeny --path /opt/VBoxGuestAdditions-7.2.2 --path /usr/sbin/VBoxService\n";

static const struct argp_option opts[] = {
    { "path", 'p', "PATH", 0, "Exact path to hide (repeatable, max 8)" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'p':
        if (env.num_paths >= MAX_CLI_PATHS) {
            fprintf(stderr, "Error: Maximum of %d paths supported\n", MAX_CLI_PATHS);
            argp_usage(state);
        }
        if (strlen(arg) >= MAX_PATH_LEN) {
            fprintf(stderr, "Path too long (max %d chars): %s\n", MAX_PATH_LEN - 1, arg);
            argp_usage(state);
        }
        strncpy(env.paths[env.num_paths], arg, MAX_PATH_LEN - 1);
        env.num_paths++;
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

/* The two path-string LSM hooks (file_open, inode_getattr) match against
 * whatever bpf_d_path() reports for the dentry the kernel actually ends up
 * checking - which, for any open()/stat() that follows a symlink (the
 * default for both unless the caller passes O_NOFOLLOW/AT_SYMLINK_NOFOLLOW),
 * is the symlink's *resolved target*, not the symlink path itself. Real
 * VirtualBox Guest Additions installs put exactly this shape under
 * /usr/{bin,sbin} (symlinks into /opt/VBoxGuestAdditions-X.Y.Z/...) -
 * confirmed live: a plain stat() on a configured symlink path went
 * straight through undenied, while lstat()-style non-following lookups
 * were correctly denied. So expand each configured path that's a symlink
 * with its resolved target too, up to MAX_HIDDEN_PATHS total. Best-effort:
 * only resolvable for paths that exist right now, same documented
 * limitation as the (device, inode) resolution below. */
static int add_expanded_path(char out[][MAX_PATH_LEN], int *out_n, const char *path)
{
    if (*out_n >= MAX_HIDDEN_PATHS)
        return 0;
    for (int i = 0; i < *out_n; i++) {
        if (strcmp(out[i], path) == 0)
            return 1; /* already present, don't waste a slot */
    }
    strncpy(out[*out_n], path, MAX_PATH_LEN - 1);
    out[*out_n][MAX_PATH_LEN - 1] = '\0';
    (*out_n)++;
    return 1;
}

static int build_expanded_paths(char out[][MAX_PATH_LEN])
{
    int n = 0;
    for (int i = 0; i < env.num_paths; i++) {
        add_expanded_path(out, &n, env.paths[i]);

        struct stat lst;
        if (lstat(env.paths[i], &lst) != 0 || !S_ISLNK(lst.st_mode))
            continue;

        char resolved[PATH_MAX];
        if (!realpath(env.paths[i], resolved))
            continue;
        if (strlen(resolved) >= MAX_PATH_LEN) {
            fprintf(stderr, "[!] Resolved target of %s too long (max %d chars), skipping: %s\n",
                    env.paths[i], MAX_PATH_LEN - 1, resolved);
            continue;
        }
        if (!add_expanded_path(out, &n, resolved)) {
            fprintf(stderr, "[!] No room left to also cover resolved target of %s: %s\n",
                    env.paths[i], resolved);
        }
    }
    return n;
}

/* Checks whether BPF LSM is even active, without attempting to load
 * anything - this part is genuinely knowable upfront, unlike the
 * lockdown question (see main()'s comment at the load() call). */
static int bpf_lsm_active(void)
{
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f)
        return 0;
    char buf[512];
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    if (n == 0)
        return 0;
    buf[n] = '\0';
    /* Match "bpf" as a whole comma-separated token, not a substring of
     * some other LSM name. */
    char *tok = strtok(buf, ",\n");
    while (tok) {
        if (strcmp(tok, "bpf") == 0)
            return 1;
        tok = strtok(NULL, ",\n");
    }
    return 0;
}

static void print_lockdown_context(void)
{
    FILE *f = fopen("/sys/kernel/security/lockdown", "r");
    if (!f)
        return;
    char buf[128];
    if (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';
        fprintf(stderr, "    Current lockdown mode: %s\n", buf);
        fprintf(stderr, "    (if this isn't '[none]', lockdown *may* be the cause - "
                        "see 'man kernel_lockdown' - but this isn't confirmed for every\n"
                        "    lockdown level, so don't assume it without checking)\n");
    }
    fclose(f);
}

int main(int argc, char **argv)
{
    struct pathdeny_bpf *skel;
    int err;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.num_paths == 0) {
        fprintf(stderr, "Error: at least one --path is required\n");
        return 1;
    }

    /* Don't predict whether the load will succeed beyond this one
     * genuinely-knowable-upfront fact - see the lockdown finding in the
     * plan for why a lockdown-state-based prediction was deliberately
     * not implemented. */
    if (!bpf_lsm_active()) {
        fprintf(stderr, "[!] BPF LSM is not active on this kernel "
                        "('bpf' not listed in /sys/kernel/security/lsm)\n");
        fprintf(stderr, "    pathdeny needs CONFIG_BPF_LSM and 'bpf' in the active LSM stack.\n");
        fprintf(stderr, "    Skipping - every other nogitsune spoofer is unaffected.\n");
        return 1;
    }

    if (!setup()) {
        fprintf(stderr, "Failed to do common setup\n");
        return 1;
    }

    skel = pathdeny_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    char expanded_paths[MAX_HIDDEN_PATHS][MAX_PATH_LEN];
    int num_expanded = build_expanded_paths(expanded_paths);

    skel->rodata->num_hidden_paths = num_expanded;
    for (int i = 0; i < num_expanded; i++) {
        strncpy(skel->rodata->hidden_paths[i], expanded_paths[i], MAX_PATH_LEN - 1);
        skel->rodata->hidden_path_lens[i] = (int)strlen(expanded_paths[i]);
    }

    /* access()'s inode_permission hook has no path/dentry at all, so it
     * matches by (device, inode) instead, resolved via stat() (which
     * itself follows symlinks, so this already covers the resolved target
     * without needing the expanded path list above). Best-effort: only
     * resolvable for paths that exist right now - this is the documented
     * structural limitation for access() coverage specifically, not a
     * bug. */
    int num_inodes = 0;
    for (int i = 0; i < env.num_paths; i++) {
        struct stat st;
        if (stat(env.paths[i], &st) == 0) {
            skel->rodata->hidden_inos[num_inodes] = (unsigned long)st.st_ino;
            skel->rodata->hidden_devs[num_inodes] = (unsigned int)st.st_dev;
            num_inodes++;
        } else {
            fprintf(stderr, "[!] %s does not exist yet - access() coverage for it "
                            "will not apply until pathdeny is restarted after it appears\n",
                    env.paths[i]);
        }
    }
    skel->rodata->num_hidden_inodes = num_inodes;

    err = pathdeny_bpf__load(skel);
    if (err) {
        fprintf(stderr, "[!] Failed to load BPF LSM program: %d (%s)\n", err, strerror(-err));
        fprintf(stderr, "    'bpf' is active in /sys/kernel/security/lsm, but the actual\n");
        fprintf(stderr, "    program load still failed - this is a different cause than\n");
        fprintf(stderr, "    \"not compiled in\" (which was already ruled out above).\n");
        print_lockdown_context();
        fprintf(stderr, "    Skipping - every other nogitsune spoofer is unaffected.\n");
        goto cleanup;
    }

    err = pathdeny_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
        goto cleanup;
    }

    printf("============================================\n");
    printf("  Exact-Path Hider (BPF LSM)\n");
    printf("============================================\n\n");
    printf("Hiding paths (open/stat/access all denied with ENOENT):\n");
    for (int i = 0; i < num_expanded; i++) {
        printf("  - %s\n", expanded_paths[i]);
    }
    if (num_expanded > env.num_paths) {
        printf("    (%d of these are resolved symlink targets, covered automatically)\n",
               num_expanded - env.num_paths);
    }
    if (num_inodes < env.num_paths) {
        printf("\n%d of %d paths didn't exist at startup - access() denial only\n",
               env.num_paths - num_inodes, env.num_paths);
        printf("applies to the %d that did (open/stat coverage applies to all %d).\n",
               num_inodes, env.num_paths);
    }
    printf("\nPress Ctrl+C to stop...\n");

    while (!exiting) sleep(1);

cleanup:
    pathdeny_bpf__destroy(skel);
    printf("\nStopped.\n");
    return err < 0 ? -err : err;
}
