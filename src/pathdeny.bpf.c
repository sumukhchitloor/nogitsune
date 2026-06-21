// SPDX-License-Identifier: GPL-2.0
/*
 * pathdeny.bpf.c - BPF LSM-based exact-path hiding.
 *
 * Defeats direct open()/stat()/access() probing of known paths - the gap
 * fshide's directory-listing hiding can't close (a caller that already
 * knows the exact path doesn't need to enumerate the directory).
 *
 * Three hooks, validated individually via live load+attach+test prototypes
 * before being generalized here (not assumed from documentation):
 *
 *  - lsm/file_open       (struct file *file)            -> open()/cat
 *  - lsm/inode_getattr   (struct path *path)             -> stat()
 *  - lsm/inode_permission (struct inode *inode, int mask) -> access()
 *
 * The first two hooks both expose a struct path (directly, or via
 * file->f_path) and use bpf_d_path() for path-string matching. The third
 * does NOT expose any path/dentry at all on this kernel - confirmed the
 * hard way: an earlier attempt used the wrong parameter signature (copied
 * from a BTF FUNC_PROTO that turned out to belong to a different,
 * adjacent function in bpftool's ID-sorted dump output, not this one),
 * which loaded and ran without error while silently reading garbage
 * memory and never matching anything. The real signature only gives an
 * inode, so that hook matches by (device, inode number) instead, resolved
 * once via a userspace stat() of each configured path before load.
 *
 * STRUCTURAL CONSEQUENCE: inode_permission's (dev, inode) matching only
 * covers paths that already existed when pathdeny started - unlike the
 * two path-string hooks, which match dynamically regardless of whether
 * the path existed at startup. This is a real, documented limitation of
 * the technique, not a bug.
 *
 * Patterns are NOT loop-scanned text substitution (unlike dmi_spoof/
 * kmsg_spoof) - these hooks DENY the operation outright (return -ENOENT),
 * since unlike a read() buffer, a permission-check hook's return value
 * *is* the syscall's result for the caller.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#if NOGITSUNE_DEBUG
#define log_bpf(fmt, ...) bpf_printk(fmt, ##__VA_ARGS__)
#else
#define log_bpf(fmt, ...)
#endif

#define ENOENT 2
/* 16, not 8: userspace expands each configured symlink path into two
 * entries here (the symlink itself + its resolved real target - see
 * pathdeny.c) so the path-string hooks below also catch callers that
 * follow the symlink, which the kernel resolves before these LSM hooks
 * fire (confirmed live: stat() on a configured symlink path was *not*
 * denied, only lstat()-style non-following lookups were). */
#define MAX_HIDDEN_PATHS 16
#define MAX_PATH_LEN 80

/* Path-string list - used by the two bpf_d_path()-capable hooks
 * (file_open, inode_getattr). Covers every configured path regardless of
 * whether it existed when pathdeny started. */
const volatile int num_hidden_paths = 0;
const volatile char hidden_paths[MAX_HIDDEN_PATHS][MAX_PATH_LEN];
const volatile int hidden_path_lens[MAX_HIDDEN_PATHS];

/* (device, inode) list - used only by inode_permission (access()), which
 * has no path/dentry available. Only populated for paths that existed
 * at startup (see the structural consequence noted above) - so
 * num_hidden_inodes can be less than num_hidden_paths. */
const volatile int num_hidden_inodes = 0;
const volatile unsigned long hidden_inos[MAX_HIDDEN_PATHS];
const volatile unsigned int hidden_devs[MAX_HIDDEN_PATHS];

/* Compares p[0..len-1] against hidden_paths[idx][0..len-1] AND requires
 * p[len] == '\0' for an exact (not prefix) match - p[len] is a
 * runtime-variable index, but len is bounded to [1, MAX_PATH_LEN-1] by
 * the guard below *before* any access, in straight-line code with no
 * loop/back-edge to lose that bound across (unlike the verifier-bound
 * loss this project hit and fixed in textreplace.bpf.c, which was
 * specifically a loop-carried case). */
static __always_inline int cmp_path(const char *p, int idx)
{
    int len = hidden_path_lens[idx];
    if (len <= 0 || len > MAX_PATH_LEN - 1)
        return 0;

    if (len > 0 && p[0] != hidden_paths[idx][0]) return 0;
    if (len > 1 && p[1] != hidden_paths[idx][1]) return 0;
    if (len > 2 && p[2] != hidden_paths[idx][2]) return 0;
    if (len > 3 && p[3] != hidden_paths[idx][3]) return 0;
    if (len > 4 && p[4] != hidden_paths[idx][4]) return 0;
    if (len > 5 && p[5] != hidden_paths[idx][5]) return 0;
    if (len > 6 && p[6] != hidden_paths[idx][6]) return 0;
    if (len > 7 && p[7] != hidden_paths[idx][7]) return 0;
    if (len > 8 && p[8] != hidden_paths[idx][8]) return 0;
    if (len > 9 && p[9] != hidden_paths[idx][9]) return 0;
    if (len > 10 && p[10] != hidden_paths[idx][10]) return 0;
    if (len > 11 && p[11] != hidden_paths[idx][11]) return 0;
    if (len > 12 && p[12] != hidden_paths[idx][12]) return 0;
    if (len > 13 && p[13] != hidden_paths[idx][13]) return 0;
    if (len > 14 && p[14] != hidden_paths[idx][14]) return 0;
    if (len > 15 && p[15] != hidden_paths[idx][15]) return 0;
    if (len > 16 && p[16] != hidden_paths[idx][16]) return 0;
    if (len > 17 && p[17] != hidden_paths[idx][17]) return 0;
    if (len > 18 && p[18] != hidden_paths[idx][18]) return 0;
    if (len > 19 && p[19] != hidden_paths[idx][19]) return 0;
    if (len > 20 && p[20] != hidden_paths[idx][20]) return 0;
    if (len > 21 && p[21] != hidden_paths[idx][21]) return 0;
    if (len > 22 && p[22] != hidden_paths[idx][22]) return 0;
    if (len > 23 && p[23] != hidden_paths[idx][23]) return 0;
    if (len > 24 && p[24] != hidden_paths[idx][24]) return 0;
    if (len > 25 && p[25] != hidden_paths[idx][25]) return 0;
    if (len > 26 && p[26] != hidden_paths[idx][26]) return 0;
    if (len > 27 && p[27] != hidden_paths[idx][27]) return 0;
    if (len > 28 && p[28] != hidden_paths[idx][28]) return 0;
    if (len > 29 && p[29] != hidden_paths[idx][29]) return 0;
    if (len > 30 && p[30] != hidden_paths[idx][30]) return 0;
    if (len > 31 && p[31] != hidden_paths[idx][31]) return 0;
    if (len > 32 && p[32] != hidden_paths[idx][32]) return 0;
    if (len > 33 && p[33] != hidden_paths[idx][33]) return 0;
    if (len > 34 && p[34] != hidden_paths[idx][34]) return 0;
    if (len > 35 && p[35] != hidden_paths[idx][35]) return 0;
    if (len > 36 && p[36] != hidden_paths[idx][36]) return 0;
    if (len > 37 && p[37] != hidden_paths[idx][37]) return 0;
    if (len > 38 && p[38] != hidden_paths[idx][38]) return 0;
    if (len > 39 && p[39] != hidden_paths[idx][39]) return 0;
    if (len > 40 && p[40] != hidden_paths[idx][40]) return 0;
    if (len > 41 && p[41] != hidden_paths[idx][41]) return 0;
    if (len > 42 && p[42] != hidden_paths[idx][42]) return 0;
    if (len > 43 && p[43] != hidden_paths[idx][43]) return 0;
    if (len > 44 && p[44] != hidden_paths[idx][44]) return 0;
    if (len > 45 && p[45] != hidden_paths[idx][45]) return 0;
    if (len > 46 && p[46] != hidden_paths[idx][46]) return 0;
    if (len > 47 && p[47] != hidden_paths[idx][47]) return 0;
    if (len > 48 && p[48] != hidden_paths[idx][48]) return 0;
    if (len > 49 && p[49] != hidden_paths[idx][49]) return 0;
    if (len > 50 && p[50] != hidden_paths[idx][50]) return 0;
    if (len > 51 && p[51] != hidden_paths[idx][51]) return 0;
    if (len > 52 && p[52] != hidden_paths[idx][52]) return 0;
    if (len > 53 && p[53] != hidden_paths[idx][53]) return 0;
    if (len > 54 && p[54] != hidden_paths[idx][54]) return 0;
    if (len > 55 && p[55] != hidden_paths[idx][55]) return 0;
    if (len > 56 && p[56] != hidden_paths[idx][56]) return 0;
    if (len > 57 && p[57] != hidden_paths[idx][57]) return 0;
    if (len > 58 && p[58] != hidden_paths[idx][58]) return 0;
    if (len > 59 && p[59] != hidden_paths[idx][59]) return 0;
    if (len > 60 && p[60] != hidden_paths[idx][60]) return 0;
    if (len > 61 && p[61] != hidden_paths[idx][61]) return 0;
    if (len > 62 && p[62] != hidden_paths[idx][62]) return 0;
    if (len > 63 && p[63] != hidden_paths[idx][63]) return 0;
    if (len > 64 && p[64] != hidden_paths[idx][64]) return 0;
    if (len > 65 && p[65] != hidden_paths[idx][65]) return 0;
    if (len > 66 && p[66] != hidden_paths[idx][66]) return 0;
    if (len > 67 && p[67] != hidden_paths[idx][67]) return 0;
    if (len > 68 && p[68] != hidden_paths[idx][68]) return 0;
    if (len > 69 && p[69] != hidden_paths[idx][69]) return 0;
    if (len > 70 && p[70] != hidden_paths[idx][70]) return 0;
    if (len > 71 && p[71] != hidden_paths[idx][71]) return 0;
    if (len > 72 && p[72] != hidden_paths[idx][72]) return 0;
    if (len > 73 && p[73] != hidden_paths[idx][73]) return 0;
    if (len > 74 && p[74] != hidden_paths[idx][74]) return 0;
    if (len > 75 && p[75] != hidden_paths[idx][75]) return 0;
    if (len > 76 && p[76] != hidden_paths[idx][76]) return 0;
    if (len > 77 && p[77] != hidden_paths[idx][77]) return 0;
    if (len > 78 && p[78] != hidden_paths[idx][78]) return 0;
    if (len > 79 && p[79] != hidden_paths[idx][79]) return 0;

    /* Require an exact match, not just a matching prefix - p must end
     * right where the configured pattern does. */
    if (p[len] != '\0')
        return 0;

    return 1;
}

static __always_inline int check_path_match(const char *p)
{
    if (num_hidden_paths > 0 && cmp_path(p, 0)) return 1;
    if (num_hidden_paths > 1 && cmp_path(p, 1)) return 1;
    if (num_hidden_paths > 2 && cmp_path(p, 2)) return 1;
    if (num_hidden_paths > 3 && cmp_path(p, 3)) return 1;
    if (num_hidden_paths > 4 && cmp_path(p, 4)) return 1;
    if (num_hidden_paths > 5 && cmp_path(p, 5)) return 1;
    if (num_hidden_paths > 6 && cmp_path(p, 6)) return 1;
    if (num_hidden_paths > 7 && cmp_path(p, 7)) return 1;
    if (num_hidden_paths > 8 && cmp_path(p, 8)) return 1;
    if (num_hidden_paths > 9 && cmp_path(p, 9)) return 1;
    if (num_hidden_paths > 10 && cmp_path(p, 10)) return 1;
    if (num_hidden_paths > 11 && cmp_path(p, 11)) return 1;
    if (num_hidden_paths > 12 && cmp_path(p, 12)) return 1;
    if (num_hidden_paths > 13 && cmp_path(p, 13)) return 1;
    if (num_hidden_paths > 14 && cmp_path(p, 14)) return 1;
    if (num_hidden_paths > 15 && cmp_path(p, 15)) return 1;
    return 0;
}

static __always_inline int cmp_inode(unsigned long ino, unsigned int dev, int idx)
{
    return ino == hidden_inos[idx] && dev == hidden_devs[idx];
}

static __always_inline int check_inode_match(unsigned long ino, unsigned int dev)
{
    if (num_hidden_inodes > 0 && cmp_inode(ino, dev, 0)) return 1;
    if (num_hidden_inodes > 1 && cmp_inode(ino, dev, 1)) return 1;
    if (num_hidden_inodes > 2 && cmp_inode(ino, dev, 2)) return 1;
    if (num_hidden_inodes > 3 && cmp_inode(ino, dev, 3)) return 1;
    if (num_hidden_inodes > 4 && cmp_inode(ino, dev, 4)) return 1;
    if (num_hidden_inodes > 5 && cmp_inode(ino, dev, 5)) return 1;
    if (num_hidden_inodes > 6 && cmp_inode(ino, dev, 6)) return 1;
    if (num_hidden_inodes > 7 && cmp_inode(ino, dev, 7)) return 1;
    if (num_hidden_inodes > 8 && cmp_inode(ino, dev, 8)) return 1;
    if (num_hidden_inodes > 9 && cmp_inode(ino, dev, 9)) return 1;
    if (num_hidden_inodes > 10 && cmp_inode(ino, dev, 10)) return 1;
    if (num_hidden_inodes > 11 && cmp_inode(ino, dev, 11)) return 1;
    if (num_hidden_inodes > 12 && cmp_inode(ino, dev, 12)) return 1;
    if (num_hidden_inodes > 13 && cmp_inode(ino, dev, 13)) return 1;
    if (num_hidden_inodes > 14 && cmp_inode(ino, dev, 14)) return 1;
    if (num_hidden_inodes > 15 && cmp_inode(ino, dev, 15)) return 1;
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(deny_file_open, struct file *file)
{
    char p[MAX_PATH_LEN];
    long len = bpf_d_path(&file->f_path, p, sizeof(p));
    if (len < 0)
        return 0;

    if (check_path_match(p)) {
        log_bpf("[PATHDENY] denying file_open on %s", p);
        return -ENOENT;
    }
    return 0;
}

SEC("lsm/inode_getattr")
int BPF_PROG(deny_inode_getattr, struct path *path)
{
    char p[MAX_PATH_LEN];
    long len = bpf_d_path(path, p, sizeof(p));
    if (len < 0)
        return 0;

    if (check_path_match(p)) {
        log_bpf("[PATHDENY] denying inode_getattr (stat) on %s", p);
        return -ENOENT;
    }
    return 0;
}

SEC("lsm/inode_permission")
int BPF_PROG(deny_inode_permission, struct inode *inode, int mask)
{
    unsigned long ino = BPF_CORE_READ(inode, i_ino);
    unsigned int dev = BPF_CORE_READ(inode, i_sb, s_dev);

    if (check_inode_match(ino, dev)) {
        log_bpf("[PATHDENY] denying inode_permission on ino=%lu dev=%u", ino, dev);
        return -ENOENT;
    }
    return 0;
}
