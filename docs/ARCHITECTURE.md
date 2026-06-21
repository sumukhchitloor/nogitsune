# Architecture

This is the deep technical reference: every hook point, every BPF map, the verifier
problems that were actually hit (and how), and how the userspace CLI orchestrates 16
independent BPF programs as one tool. For user-facing usage see the
[README](../README.md); for the JSON profile schema see
[CONFIGURATION.md](CONFIGURATION.md).

Nothing here is aspirational - every claim is either read directly from the source in
this repository or was confirmed by running the tool and observing the result (the BPF
verifier sections in particular come from real rejections hit during development, not
from documentation).

---

## 1. Design principles

- **Spoof in memory, never on disk.** No file under `/sys`, `/proc`, or `/opt` is ever
  written to. Every spoofer intercepts a syscall *after* the kernel has already filled
  in the real data and rewrites the userspace-bound copy before the calling process sees
  it. `cat /sys/class/dmi/id/sys_vendor` on a quiescent system (no spoofer attached)
  still returns the real, unmodified value.
- **One process per spoofer, not one shared BPF object.** `nogitsune spoof` `fork()`s a
  separate child process per active spoofer (`dmi_spoof`, `meminfo_spoof`, `pci_spoof`,
  ...), each loading and attaching its own independent BPF program. This is a deliberate
  tradeoff over a single monolithic BPF object: it means `--dmi --mac` can load only two
  spoofers without touching the others, a crash in one spoofer's userspace loader
  doesn't take down any other, and `nogitsune stop` can cascade a clean shutdown by
  signaling each child individually. The cost is N small ELF binaries and N skeleton
  loads instead of one - acceptable given spoofers number in the teens, not thousands.
- **Detect, don't assume, hardware/kernel facts.** Which hardware-identity spoofer to
  run (`dmi_spoof` vs `devicetree_spoof`), whether `cpuinfo_spoof` makes sense at all,
  and whether `pathdeny` can even load are all decided by *probing the running system*
  (`file_exists("/sys/class/dmi/id/sys_vendor")`, `/sys/kernel/security/lsm` content,
  `__aarch64__` at compile time only for the one case - the x86 "hypervisor" CPUID flag
  format - that's genuinely architecture-specific, not OS-version-specific) - never by
  guessing from `uname -m` alone.
- **Document the gap instead of silently leaving it.** Every spoofer in this codebase
  has a known, written-down limit to what it can intercept (see README "Known
  Limitations" and the per-file header comments). Several of those limits were found by
  deliberately trying to break the tool (see §6 and §7 below).

---

## 2. The three interception techniques

Every one of the 16 BPF-backed tools uses exactly one of these three techniques.

### 2.A. Read-buffer rewriting (the dominant pattern)

Used by: `dmi_spoof`, `devicetree_spoof`, `cpuinfo_spoof`, `meminfo_spoof`,
`uptime_spoof`, `pci_spoof`, `modules_hide`, `kmsg_spoof`, `textreplace` (MAC-file,
disk-model).

The shape is the same four-tracepoint state machine in every one of these programs:

```
sys_enter_openat  -> is this filename one we care about? if so, remember pid_tgid -> "tracking"
sys_enter_read    -> are we tracking this pid_tgid? if so, remember the userspace buffer pointer
sys_exit_read     -> are we tracking this pid_tgid? if so:
                       - bail if the real read() returned <= 0 bytes (error, or EOF)
                       - bpf_probe_write_user() the spoofed bytes into that buffer
sys_enter_close   -> stop tracking this pid_tgid (cleans up both hash map entries)
```

Two `BPF_MAP_TYPE_HASH` maps carry state across these four tracepoint invocations,
keyed by `pid_tgid` (`bpf_get_current_pid_tgid()`, unique per thread, not just per
process - necessary because `open()`/`read()`/`close()` for one logical read can in
principle interleave across threads of the same multi-threaded reader):

- a "this pid_tgid opened a file we care about" presence map (sometimes carrying the
  matched file index when one program handles several files, e.g. `dmi_spoof`'s 15
  file variants - see §8)
- a "this pid_tgid's pending read() targets this userspace address" map

`sys_exit_read` is the only place a write happens, and it's also where the byte budget
is decided: **never write more bytes than the kernel itself wrote** (`ret`, the
syscall's actual return value). This protects against two distinct failure modes
covered in §4.

The matching step (`is_dmi_path()`, `is_cpuinfo()`, `is_proc_modules()`, etc.) compares
against the filename argument captured at `sys_enter_openat`, not at `sys_enter_read` -
deliberately, because the read's file descriptor doesn't carry a path string at all by
the time `read()` is called; the path is only ever visible at `open()`/`openat()` time.
`dmi_spoof` and `devicetree_spoof` match by **path suffix**, not full path, specifically
so the same matcher covers both `/sys/class/dmi/id/sys_vendor` and the
`/sys/devices/virtual/dmi/id/sys_vendor` alias the kernel also exposes for the same
data.

### 2.B. Directory-listing entry splicing (`getdents64` patching)

Used by: `pidhide` (hides PIDs from `/proc`), `fshide` (hides arbitrary filename
prefixes from any directory listing).

`ls`, `find`, `ps`, and every other directory-listing tool ultimately call
`getdents64(fd, buf, count)`, which the kernel fills with a packed sequence of
`struct linux_dirent64` records back-to-back in one buffer:

```
struct linux_dirent64 {
    u64 d_ino;
    s64 d_off;
    u16 d_reclen;   /* byte length of *this* record, including this header */
    u8  d_type;
    char d_name[];  /* NUL-terminated, padded to alignment */
};
```

To hide an entry, you cannot simply blank its `d_name` (the slot is still there, with a
zero-length or garbage name - `ls` would print an empty or corrupted line, which is
itself a tell). The actual technique: walk the buffer back-to-back, and when a
to-be-hidden entry is found, **rewrite the *previous* record's `d_reclen`** to span both
itself and the hidden one:

```
[entry A][entry B (HIDE)][entry C]      d_reclen(A) covers only A
                  |
                  v  splice: d_reclen(A) += d_reclen(B)
[entry A     ===========][entry C]      a single walk over the buffer now steps
                                          straight from A to C - B is never visited
```

The caller's own buffer-walking loop (which only ever advances by `d_reclen`) skips
straight over the spliced region. The entry isn't blanked, scrambled, or removed from
the syscall's reported byte count - it's structurally invisible to anything that walks
the record chain the normal way, which is the only way anything ever does walk it.

This needs **two BPF programs working together**, not one:

1. **Scanner** (`handle_getdents_exit`, attached directly to `sys_exit_getdents64`):
   walks records from the last position it left off at (tracked per-`pid_tgid` in
   `map_bytes_read`, since one syscall's buffer can hold more entries than a single BPF
   program invocation is allowed to loop over - see the 200-iteration cap below).
   Records the address of "the previous entry" into `map_to_patch` as it goes. When it
   finds a name that matches the hide-list, it **does not patch in place** - it
   tail-calls into the patcher (`bpf_tail_call(ctx, &map_prog_array, PROG_02)`).
2. **Patcher** (`handle_getdents_patch`, *not* attached to the tracepoint directly -
   only reachable via the scanner's tail call): re-reads the previous entry's
   `d_reclen` from `map_to_patch`, computes the merged length, and does the actual
   `bpf_probe_write_user()` splice. It then **tail-calls back into the scanner**
   (`PROG_01`) to resume scanning past the now-hidden entry, since there can be more
   than one entry to hide in the same buffer.

The scanner's per-invocation loop is capped at `200` records
(`for (int i = 0; i < 200; i++)`), not "until the buffer ends" - a BPF program has a
hard instruction-count ceiling the verifier enforces statically, so an unbounded loop
over a buffer whose size is only known at runtime cannot verify at all. If a single
`getdents64()` call returns more than 200 directory entries, the scanner exhausts its
budget, saves its position in `map_bytes_read`, and **tail-calls itself**
(`bpf_tail_call(ctx, &map_prog_array, PROG_01)`) to continue from there in a fresh
invocation - tail calls reset the instruction budget, which is exactly what makes an
effectively-unbounded buffer walk possible at all under a verifier that only ever
checks bounded, straight-line-or-backedge-free code.

`pidhide.bpf.c` and `fshide.bpf.c` are the same architecture; the only real difference
is what they match against. `pidhide` matches **fixed-width zero-padded PID strings**
stored in a writable hash map (so userspace can add/remove PIDs - and re-resolve a
`-n NAME` filter periodically, since a respawned process gets a new PID -
`pids_to_hide_map`, keyed by the literal `char[MAX_PID_LEN]` bytes
`bpf_probe_read_user_str()` reads from `d_name`, zero-padded so the same name always
hashes to the same key - see the long comment in `pidhide.bpf.c` about why the explicit
`memset` before the read matters: `bpf_probe_read_user_str()` does **not** zero-pad
trailing bytes the way `strncpy` does, so without it, stale stack bytes from a
previous, longer filename would make the same short name hash to a different key on
different iterations and silently stop matching). `fshide` matches **prefix strings**
against a read-only rodata array (`hidden_names[MAX_HIDDEN_NAMES][MAX_NAME_LEN]`,
configured once at load time, not mutated at runtime) - prefix matching is what lets one
configured entry (`"VBoxGuestAdditions"`) match a version-suffixed real directory
(`VBoxGuestAdditions-7.2.2`) without needing the exact installed version.

### 2.C. BPF LSM deny hooks (`pathdeny`)

Used by: `pathdeny` only.

The previous two techniques both modify *data the kernel already decided to return*.
`pathdeny` instead intercepts the kernel's **permission-check** layer itself, using
`SEC("lsm/...")` programs attached to LSM (Linux Security Module) hook points rather
than tracepoints. This requires `CONFIG_BPF_LSM` and `bpf` listed as an active LSM in
`/sys/kernel/security/lsm` - if either is missing, `pathdeny` checks for this explicitly
at startup and exits cleanly (see `bpf_lsm_active()` in `pathdeny.c`) without touching
any other spoofer.

Three hooks, each validated by live load+attach+test before being relied on (not
assumed from documentation alone - see the header comment in `pathdeny.bpf.c`):

| LSM hook | Covers | What's available to match on |
|---|---|---|
| `lsm/file_open` | `open()` (and anything built on it, e.g. `cat`) | `struct file *` -> `file->f_path`, readable via `bpf_d_path()` as a real path string |
| `lsm/inode_getattr` | `stat()`/`fstatat()`/`statx()` | `struct path *` directly, also via `bpf_d_path()` |
| `lsm/inode_permission` | `access()` | **only** `struct inode *` and an access `mask` - no path or dentry at all |

The first two get a real path string and do **exact-length string comparison**
(`cmp_path()` in `pathdeny.bpf.c`, manually unrolled because BPF cannot index a 2D
rodata array - `hidden_paths[idx][...]` - with a verifier-unprovable runtime `idx`; see
§6). The third hook has no path information whatsoever on this kernel (confirmed by
direct BTF inspection during development, not assumed from a header file - an earlier
attempt used the wrong parameter signature copied from an adjacent function in
bpftool's ID-sorted output, which loaded and ran *without error* while silently reading
garbage and never matching anything). Because of that, `access()` coverage instead
matches by **`(device, inode)` pair**, resolved once at startup via a userspace
`stat()` of each configured path (`pathdeny.c`'s `main()`). All three hooks return
`-ENOENT` on a match, making the denied operation look exactly like the path never
existed, rather than a permission error (which would itself be a distinguishing
artifact for anything attentive enough to check `errno`).

**The symlink-following gap (found and fixed during this project's hardening pass):**
Real VirtualBox Guest Additions installs place `/usr/sbin/VBoxService`,
`/usr/bin/VBoxClient`, `/usr/bin/VBoxControl`, and `/usr/sbin/mount.vboxsf` as
*symlinks* into a version-suffixed `/opt/VBoxGuestAdditions-X.Y.Z/...` directory - this
is the real on-disk layout, not a hypothetical. Both `lsm/file_open` and
`lsm/inode_getattr` fire on the dentry the kernel resolves *after* following a symlink
(unless the caller explicitly passes `O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`, which almost no
real probing code does - `cat`, `stat()`, and `nogitsune status`'s own check all follow
symlinks by default). `bpf_d_path()` at that point reports the **resolved target path**,
not the symlink path the caller actually typed - so a configured `hidden_paths` entry
of just `/usr/sbin/VBoxService` silently failed to match, and the real binary was fully
readable straight through. This was confirmed live: a coreutils `stat` (which does *not*
follow symlinks by default - it reports the link itself) on the configured path was
correctly denied, while `cat` (which *does* follow it) sailed straight through to the
real file.

The fix, in `pathdeny.c`'s `build_expanded_paths()`: for every configured path, check
via `lstat()` whether it's a symlink, and if so, also resolve its real target with
`realpath()` and add *that* string as a second matched path. Both the symlink and its
resolved target now sit in the BPF program's `hidden_paths` rodata array (bumped from 8
to 16 slots specifically to leave room for this expansion - see `pathdeny.bpf.c`). The
`(device, inode)` resolution for the `access()` hook didn't need this fix at all: a
userspace `stat()` already follows symlinks transparently, so it was already resolving
to the real target's inode the whole time - only the two *path-string* hooks had the
gap, because string-matching is inherently more literal than inode-matching.

---

## 3. Multi-pattern / multi-occurrence scanning

Some files don't have one fixed-position value to overwrite - they may contain the
target pattern at an unknown, data-dependent byte offset, or multiple times in the same
buffer (`/sys/class/dmi/id/modalias`, `/proc/cpuinfo`'s several `hypervisor`/`cpu cores`
occurrences, `/proc/modules`, `/dev/kmsg`, legacy `syslog()`). Two different techniques
exist in this codebase for that, from two different eras of the project:

### Modern: `bpf_loop()` callback (kernel 5.17+)

Used by: `cpuinfo_spoof`, `modules_hide`, `dmi_spoof`'s modalias/uevent/raw-SMBIOS
scanner, `kmsg_spoof`.

```c
bpf_loop(len, scan_callback, &sc, 0);
```

`bpf_loop()` is a kernel *helper function* - the actual iteration happens inside the
kernel, not as unrolled/back-edge BPF bytecode. Critically, **the verifier only
statically analyzes the callback function once**, regardless of how many times the
kernel will actually invoke it at runtime. This is what makes scanning a 4096-byte
buffer for a handful of fixed string patterns at every possible byte offset tractable
at all - the equivalent hand-unrolled loop would be thousands of verifier-checked
instructions, hitting older verifiers' "8193 jumps too complex" wall (the literal error
this technique was adopted to route around - see the header comment in
`cpuinfo_spoof.bpf.c`). Each callback invocation reads a small fixed-size chunk at one
byte offset, compares it against every known pattern, writes a replacement in place if
matched, and returns `0` to keep scanning or `1` to stop early.

### Legacy: three-stage tail-call chain (`textreplace.bpf.c`)

Used by: `textreplace` (backs the MAC-address-file and disk-model spoofing, since
`pidhide`/`fshide`/`textreplace` are this codebase's oldest BPF programs, inherited from
the upstream [bad-bpf](https://github.com/pathtofile/bad-bpf) project predating this
project's own `bpf_loop()` adoption).

Before `bpf_loop()`, the same "scan an arbitrary-position substring in an
unbounded-at-verify-time buffer" problem was solved with three separate, chained BPF
programs sharing `BPF_MAP_TYPE_ARRAY` maps as scratch space, all attached to the same
`tp/syscalls/sys_exit_read` tracepoint:

1. `find_possible_addrs` - reads the buffer in small fixed chunks (`LOCAL_BUFF_SIZE`,
   16 bytes), and for every byte that matches just the *first character* of the target
   text, records that address into `map_name_addrs` (a 300-slot array map). This program
   is auto-attached directly by the skeleton's `__attach()`.
2. `check_possible_addresses` - for every candidate address recorded above, does a full
   byte-for-byte comparison against the real target text, and files genuine matches
   into `map_to_replace_addrs`.
3. `overwrite_addresses` - for every genuine match, calls `bpf_probe_write_user()` with
   the replacement text and reports success/failure over a ring buffer back to
   userspace.

Programs 2 and 3 are also auto-attached to the same tracepoint by the skeleton (every
`SEC("tp/...")` program with a recognized attach type gets attached when
`*_bpf__attach()` runs) - but they each bail out immediately
(`bpf_map_lookup_elem(&map_buff_addrs, ...)` returns NULL) on every read() that isn't
the one currently being processed, so this redundant direct attachment is harmless,
not a second active code path. Their *real* invocation is via `bpf_tail_call()` chaining
from program 1, in sequence, within the handling of one single `sys_exit_read` event.
This three-stage "find candidate first-bytes -> verify full match -> patch" dance exists
specifically to keep any one program's static instruction count low enough to pass an
older verifier (the source comment in `textreplace.bpf.c` is explicit about this: *"all
very convoluted, but is required to keep the program complexity and size low enough to
pass the verifier checks"*) - `bpf_loop()` made this unnecessary for every BPF program
written after it was adopted, but `textreplace` was never rewritten since it still
works correctly and is shared by two different spoofing targets (MAC file, disk model)
via CLI arguments rather than being its own dedicated tool.

---

## 4. Fixed-width vs. dynamic-length writes

`bpf_probe_write_user(dst, src, len)` needs a `len` the BPF verifier can statically
prove is safe - and getting that number right, for a configurable-length replacement
value being written into a buffer of unknown real length, is the single most
error-prone part of this codebase. Two real classes of bug were hit and fixed here
(not hypothetical - see §6 for the verifier-side half of this story):

- **Never write more than the kernel actually returned.** The real file's current
  content might be *shorter* than the configured replacement (e.g. a custom DMI profile
  with a 28-character vendor string overwriting a host whose real `sys_vendor` file is
  only 13 bytes long including the trailing newline). Every read-buffer-rewriting
  spoofer clamps its write length to `min(configured_value_width, ret)`, where `ret` is
  the syscall's actual return value - this is what `dmi_spoof.bpf.c`'s comment calls a
  "fixed-width overwrite": the rodata field itself (`fake0[32]`, `fake_uptime_line[64]`,
  etc.) is always allocated at its maximum possible width and zero-padded past the
  configured value, so writing any prefix of it (up to `ret` bytes) is always
  byte-for-byte correct, never reads past the configured value into uninitialized
  rodata, and never leaves stale trailing bytes from whatever the field held before
  (since BPF rodata is reset to whatever userspace wrote into the skeleton before load,
  not the field's previous runtime content).
- **Never claim a write size the verifier can't prove is at least 1.**
  `bpf_probe_write_user`'s size argument has type `ARG_CONST_SIZE` in the kernel's
  helper signature - the verifier requires a *provable* lower bound of at least 1, not
  just "happens to be non-negative." A clamp chain that's only provably `>= 0` (e.g.
  `cpucount_spoof.bpf.c`'s three-way `min(MASK_BUF_SIZE, req_len, ret)`) gets rejected
  at load time with `"invalid zero-sized read"`, even though the value is *never
  actually* 0 at runtime in practice - the verifier doesn't get to use "in practice,"
  only what it can statically prove. The fix is an explicit `if (wlen == 0) return 0;`
  immediately before the call, which narrows the verifier's tracked bound to exclude
  zero from that point forward.

---

## 5. CO-RE and the `vmlinux.h` pipeline

Every `.bpf.c` file `#include`s a single generated `vmlinux.h` containing the *entire*
kernel's BTF (BPF Type Format) type information - every struct, every field, every
offset - as plain C type declarations. This is what lets one compiled `.bpf.o` work
correctly across different kernel versions without recompilation: field accesses like
`BPF_CORE_READ(task, real_parent, tgid)` or `bpf_d_path(&file->f_path, ...)` don't bake
in a fixed byte offset at compile time. Instead, the compiler emits a *relocation
record* (`CO-RE relocation`, visible in `libbpf`'s load-time debug output as e.g.
`CO-RE relocating [19] struct trace_event_raw_sys_enter: found target candidate [4248]
struct trace_event_raw_sys_enter in [vmlinux]`), and `libbpf` patches the actual byte
offset into the loaded program **at load time**, using the *running* kernel's own BTF
(`/sys/kernel/btf/vmlinux`) to look up where that field really lives on this specific
kernel. The same compiled `.bpf.o` is therefore portable across kernel versions that
moved a struct field around, as long as both kernels expose BTF.

The Makefile's `vmlinux.h` resolution order, per architecture:

1. **Preferred:** dump the *running* kernel's own BTF via `bpftool btf dump file
   /sys/kernel/btf/vmlinux format c`, giving CO-RE relocations the exact target they're
   built for.
2. **Fallback:** if `/sys/kernel/btf/vmlinux` doesn't exist (older kernel, BTF stripped
   at build time), copy a checked-in `vmlinux/<arch>/vmlinux.h` instead - one per
   supported architecture (`x86`, `arm64`, `arm`, `riscv`, `powerpc`, `loongarch`),
   generated once ahead of time from a representative kernel and committed to the repo
   specifically so the build doesn't hard-fail on a host with BTF support compiled out.

`bpftool` itself is built from source as a git submodule (`../bpftool`, which embeds
`../libbpf` as its own submodule) specifically for this `btf dump` step and for
generating each `.bpf.o`'s userspace skeleton header (`bpftool gen skeleton`) - there's
no dependency on a system-installed `bpftool` package, which avoids a version mismatch
between the tool generating skeletons and the `libbpf.a` they're linked against.

---

## 6. BPF verifier bugs actually hit in this codebase

These aren't theoretical "the verifier might reject this" warnings - they're real
`-EACCES` rejections hit during this project's hardening pass, with the exact verifier
log and the fix that resolved each one.

### 6.A. Re-reading a context field loses its previously-proven bound

`uptime_spoof.bpf.c`'s `handle_read_exit()` originally read `ctx->ret` (the tracepoint's
syscall return value) **three separate times**:

```c
if (ctx->ret <= 0) return 0;                  // load #1 - proves ret > 0 for THIS register
unsigned int wlen = fake_uptime_len;
if ((long)wlen > ctx->ret)                     // load #2 - a NEW, unrelated scalar read
    wlen = (unsigned int)ctx->ret;              // load #3 - ALSO a new, unrelated read
bpf_probe_write_user(..., wlen);                // verifier: "R3 min value is negative"
```

The verifier tracks value *bounds* per register, established at the point a value is
produced (here, each `*(u64 *)(ctx + 16)` load instruction). The `> 0` check at load #1
narrows *that specific register's* bound - it does not retroactively apply to a
*different* load of the same memory location issued later, even though, semantically,
nothing wrote to `ctx->ret` in between. Each reload is a fresh, unbounded scalar as far
as static analysis is concerned, so by the third reload, the verifier has lost every
bound the first check established, and can no longer prove the value passed to
`bpf_probe_write_user()`'s `len` argument is non-negative.

The fix (already the established pattern elsewhere in this codebase, e.g.
`dmi_spoof.bpf.c`'s `handle_read_exit()`): read the context field into a **local
variable once**, and reuse that variable for every subsequent check:

```c
long ret = ctx->ret;       // ONE load
if (ret <= 0) return 0;     // bound now travels with this one register/stack-slot
unsigned int wlen = fake_uptime_len;
if ((long)wlen > ret)
    wlen = (unsigned int)ret;
bpf_probe_write_user(..., wlen);   // verifier can now prove wlen's range
```

A genuinely local variable (even one the compiler spills to the BPF stack) is something
the verifier *does* track bounds for precisely across reloads from that stack slot -
the loss only happens for direct, repeated reads of context-pointer memory.

### 6.B. A provably-`>= 0` bound isn't enough for `bpf_probe_write_user`'s size argument

`cpucount_spoof.bpf.c` already cached `ctx->ret` correctly (per §6.A) - and still hit a
different rejection:

```c
unsigned int wlen = MASK_BUF_SIZE;       // 32
if (req_len < wlen) wlen = req_len;       // now provably in [0, 32)
if ((unsigned long)ret < wlen) wlen = (unsigned int)ret;  // still provably in [0, 32)
bpf_probe_write_user(..., wlen);          // verifier: "R3 invalid zero-sized read: u64=[0,31]"
```

Every clamp here was individually correct and the verifier's printed range
(`u64=[0,31]`) proves it *was* tracking the bound properly this time - the problem is
that `bpf_probe_write_user`'s helper signature requires the size argument to be
provably **at least 1**, and `[0, 31]` includes `0`. `req_len` (a syscall argument the
verifier has no way to know glibc always passes as 128+ in practice) is, *statically*,
allowed to be `0`, so the verifier correctly refuses to assume it never will be.

The fix: an explicit, unconditional guard immediately before the call:

```c
if (wlen == 0) return 0;
bpf_probe_write_user(..., wlen);   // now provably >= 1
```

This is a one-line, zero-cost fix precisely because it's a single direct comparison,
not a reload - the verifier narrows the bound from the comparison itself rather than
needing to re-derive it from anything upstream.

**Takeaway for any future spoofer added to this codebase:** if a write-size argument
is derived from more than one runtime value (request length, real read() return value,
a configured maximum), (1) cache every external/context value used in the derivation
into a true local variable exactly once, and (2) add an explicit `== 0` guard
immediately before any `bpf_probe_write_user()`/`bpf_probe_read_*` call whose size
argument isn't a compile-time constant - even if the value can never actually be zero
at runtime, the verifier needs static proof, not a runtime guarantee.

---

## 7. Per-tool technical reference

| Tool | Hook points | Technique (§) | Key maps |
|---|---|---|---|
| `dmi_spoof` | `sys_enter_openat`, `sys_enter_read`, `sys_exit_read`, `sys_enter_close` | 2.A (12 simple files) + 3 modern (`modalias`/`uevent`/raw SMBIOS table, 4 substring patterns) | `map_file_idx`, `map_buffs` |
| `devicetree_spoof` | same 4 | 2.A, fixed-width (2 files: `model`, `compatible`) | `map_file_idx`, `map_buffs` |
| `cpuinfo_spoof` | same 4 | 3 modern (`bpf_loop`, 4 patterns: `hypervisor `, `cpu cores` digit, `siblings` digit, microcode) | `target_pids`, `read_args` |
| `meminfo_spoof` | same 4 | 2.A, fixed-width (`MemTotal` line only - always first line, no scan needed) | `map_fds`, `map_buffs` |
| `uptime_spoof` | same 4 | 2.A, fixed-width, single value (see §6.A for the verifier fix here) | `map_fds`, `map_buffs` |
| `pci_spoof` | `sys_enter_openat`, `sys_enter_read`, `sys_exit_read` | 2.A, exact 7-byte (`"0xXXXX\n"`) fixed-width swap, manually-unrolled mapping array compare | `read_buf_tracker` |
| `modules_hide` | `sys_enter_openat`, `sys_enter_read`, `sys_exit_read`, `sys_enter_close` | 3 modern (`bpf_loop`, line-start-anchored name blanking) | `target_pids`, `read_args` |
| `kmsg_spoof` | `sys_enter_openat/read/close` (for `/dev/kmsg`) **and** `sys_enter_syslog`/`sys_exit_syslog` (legacy `syslog()`) | 3 modern (`bpf_loop`, case-insensitive `vbox`/`VirtualBox` pattern blanking), two independent hook sets sharing one scan callback | `kmsg_fds`, `kmsg_read_bufs`, `syslog_bufs` |
| `ioctl_spoof` | `sys_enter_ioctl`, `sys_exit_ioctl` | direct fixed-offset struct overwrite (`ifreq.ifr_hwaddr.sa_data`, offset 18) on `SIOCGIFHWADDR` | `pending_ioctls` |
| `netlink_spoof` | `sys_enter_recvmsg`, `sys_exit_recvmsg` | walks `RTM_NEWLINK`'s `rtattr` chain for `IFLA_IFNAME`/`IFLA_ADDRESS`, overwrites the MAC attribute in place | `buffers` |
| `textreplace` (MAC-file, disk-sysblock, disk-classblock) | `sys_enter_openat/exit`, `sys_enter_read/exit`, `sys_exit_close` | 3 legacy (3-program tail-call chain, pre-`bpf_loop`) | `map_fds`, `map_buff_addrs`, `map_name_addrs`, `map_to_replace_addrs`, `map_prog_array` |
| `pidhide` | `sys_enter_getdents64`, `sys_exit_getdents64` (×2 programs) | 2.B (`d_reclen` splice, fixed-width zero-padded PID-string match) | `map_buffs`, `map_bytes_read`, `map_to_patch`, `pids_to_hide_map`, `map_prog_array` |
| `fshide` | `sys_enter_getdents64`, `sys_exit_getdents64` (×2 programs) | 2.B (`d_reclen` splice, prefix-string match) | `map_buffs`, `map_bytes_read`, `map_to_patch`, `map_prog_array` |
| `pathdeny` | `lsm/file_open`, `lsm/inode_getattr`, `lsm/inode_permission` | 2.C (BPF LSM deny, exact path-string match + `(dev, inode)` match) | none (pure rodata config, no per-call state needed) |
| `cpucount_spoof` | `sys_enter_sched_getaffinity`, `sys_exit_sched_getaffinity` | 2.A-style, precomputed full-mask fixed-width write (see §6.B for the verifier fix here) | `map_buf_addr`, `map_req_len` |

---

## 8. Userspace orchestration (the `nogitsune` CLI)

`nogitsune.c` is pure userspace - it contains no BPF code itself. Its job is profile
management, process orchestration, and session bookkeeping for the 15 individual BPF
tool binaries plus `pidhide`.

### Profile system

A single `struct nogitsune_profile` (defined in `nogitsune.c`) holds every
spoofable value across every tool - DMI fields, MAC, CPU cores, memory size, disk
model, PCI ID mappings, hidden module/file/path lists, uptime, fake CPU count.
`init_default_profile()` populates it with the built-in Dell OptiPlex 7090 defaults;
`load_profile_from_json()` (using the vendored [cJSON](https://github.com/DaveGamble/cJSON)
library) overlays any subset of fields from a user-supplied `-c`/`--config` file on top
of those defaults, so omitted keys silently keep their default rather than zeroing out.
`profile_to_json()` is the mirror operation, used by `init-config` to write out the
*current* defaults as a starter file - meaning the schema documented in
[CONFIGURATION.md](CONFIGURATION.md) can never drift from what the code actually
accepts, since both directions go through the same field list.

### Spoofer table and process model

A static `spoofer_t spoofers[]` array maps a short name (`"hwid"`, `"cpu"`, `"mem"`,
`"mac-ioctl"`, ...) to a binary path, a human description, and an `enabled` flag.
`cmd_spoof()` decides final enablement (architecture-conditional disabling of `"cpu"`
on ARM64, `"hwid"`'s binary swapped between `dmi_spoof`/`devicetree_spoof` based on
`detect_hw_identity()`, `--dmi`/`--mac`/etc. flags narrowing to a subset, `"modules"`
staying off unless `--modules` is explicitly passed), then calls `launch_spoofer()` for
each enabled entry.

`launch_spoofer()` `fork()`s, and the child `execv()`s the target binary directly with
an argument vector built from the current profile (e.g. the `"cpu"` spoofer gets
`--cores 8 --microcode 0x000000b4`, `"artifacts-pathdeny"` gets one `--path <p>` per
configured hidden path). The parent stores the child's PID in the `spoofer_t` entry and
moves on - it does **not** wait for or verify the child stays running. This means a
spoofer that crashes immediately after `fork()` (most commonly: a BPF verifier
rejection, since stdout/stderr are redirected to `/dev/null` in the child before
`execv()`, so any diagnostic the crashed process printed is invisible) is still reported
as "loaded" by `spoof`'s summary - the process list is the only ground truth for whether
a spoofer is actually still alive (a defunct/zombie entry in `ps aux` is the tell;
running the binary manually, outside of `nogitsune`, surfaces the real error).

### Session lifecycle

- **Single active session enforcement:** `cmd_spoof()` reads `/run/nogitsune.pid` via
  `read_pidfile()` and refuses to start a second session if the PID it names is still
  alive (`kill(pid, 0) == 0`) - `nogitsune stop` must be run first.
- **Foreground mode:** after launching every spoofer, the parent writes its own PID to
  `/run/nogitsune.pid` and calls `pause()`, blocking until a signal arrives. `SIGINT`/
  `SIGTERM` both run the same handler, which sends `SIGTERM` to every tracked spoofer
  PID (and `pidhide`'s PID, if `--stealth` was used), then removes the PID file **only
  if it still names this exact process** (so a stray Ctrl+C in an unrelated `check`/
  `status`/`hide` invocation can never delete a different, still-running session's PID
  file).
- **Background mode** (`--background`/`-d`/`--daemon`): `daemonize_into_background()`
  does a single `fork()` + `setsid()` (detaching from the controlling terminal/session)
  + stdio redirection to `/var/log/nogitsune.log` (stdin to `/dev/null`), so the process
  survives the shell or SSH session that launched it being closed. The parent half
  prints the child's PID and returns immediately, handing control back to the shell.
- **`nogitsune stop`:** runs as a brand-new, unrelated process (possibly from a
  different terminal entirely) - it has no in-memory knowledge of which spoofers are
  running, only the PID file. It signals that one PID, whose own (still-running)
  `sig_handler` does the actual cascade-kill of every spoofer it personally launched.
  If the session doesn't exit within 1 second (10 × 100ms polls), `stop` escalates to
  `SIGKILL` and removes the PID file itself as a last resort.

---

## 9. Architecture-conditional behavior

| Decision | How it's actually decided | Where |
|---|---|---|
| `dmi_spoof` vs `devicetree_spoof` | `file_exists("/sys/class/dmi/id/sys_vendor")` first; else `file_exists("/proc/device-tree/model")` or `.../compatible` | `detect_hw_identity()` in `nogitsune.c` |
| Skip hardware-identity spoofing entirely | Neither of the above paths exists | same function, returns `HW_IDENTITY_NONE` |
| Skip `cpuinfo_spoof` | `#if defined(__aarch64__)` - a **compile-time** check, not a runtime probe, since this is genuinely a CPU-architecture fact (ARM64 `/proc/cpuinfo` has no x86-CPUID-derived `hypervisor` flag in any format, on any kernel) | `cmd_spoof()` in `nogitsune.c` |
| Primary disk for disk-model spoofing | Heuristic: lexicographically-first `/sys/block/*` entry (excluding `loop*`/`ram*`/`zram*`/`sr*`) that has a `device/model` file | `detect_primary_disk()` |
| Primary network interface for MAC spoofing | Heuristic: lexicographically-first non-excluded (`lo`/`docker*`/`veth*`/`br-*`/`virbr*`) interface observed `up`; falls back to lexicographic order with a printed warning if none are `up` yet | `detect_primary_iface()` |

Both heuristics are exactly that - documented as such in the README's Known
Limitations, not presented as authoritative root-filesystem/primary-NIC resolution.

---

## 10. Build system

- **`libbpf`** and **`bpftool`** are git submodules (`../libbpf`, `../bpftool`, with
  `bpftool` itself embedding its own `libbpf` submodule for its bootstrap build) - built
  from source by the top-level `Makefile`, never assumed to be present as system
  packages. This pins the exact `libbpf`/`bpftool` version this codebase was built
  against, avoiding skeleton-format mismatches between a system `bpftool` and a
  different system `libbpf.so`.
- **`vmlinux.h`** generation is described in full in §5 - live BTF dump preferred,
  checked-in per-architecture fallback otherwise.
- **`ARCH` detection** in the Makefile normalizes `uname -m` (`x86_64`->`x86`,
  `aarch64`->`arm64`, `armv7l`->`arm`, `ppc64le`->`powerpc`, `riscv64`->`riscv`,
  `loongarch64`->`loongarch`) to match both the `vmlinux/<arch>/` directory layout and
  the `-D__TARGET_ARCH_<arch>` macro CO-RE relocations key off of.
  `make NOGITSUNE_DEBUG=1` adds `-DNOGITSUNE_DEBUG=1` to every `.bpf.c` compile,
  switching every program's `log_bpf(...)` macro from a no-op to `bpf_printk()` (visible
  via `cat /sys/kernel/debug/tracing/trace_pipe`), with zero source changes required.
- **`xmake.lua`** is an alternate build path (`xmake`-based instead of `make`-based) for
  the same source tree, primarily exercised for cross-architecture builds (it sets
  `add_includedirs` per target arch against the same checked-in `vmlinux/<arch>/`
  fallback headers `make`'s fallback path uses) - both build systems compile the exact
  same `.bpf.c`/`.c` sources, neither is a second implementation to keep in sync.

---

## 11. Source layout

```
src/
├── nogitsune.c          CLI orchestrator - no BPF code, profile system, process model
├── cJSON.c / cJSON.h     vendored JSON library (profile load/save)
├── common.h              shared BPF-side definitions (tail-call slot IDs, event struct)
├── common_um.h            shared userspace setup (signal handlers, RLIMIT_MEMLOCK, libbpf logging)
├── <tool>.bpf.c           kernel-side BPF program for <tool>
├── <tool>.c               userspace loader/CLI for <tool> (argp parsing, skeleton load+attach)
└── vmlinux.h              x86 BTF fallback (other archs under ../vmlinux/<arch>/)
vmlinux/<arch>/vmlinux.h   per-architecture checked-in BTF fallback (see §5)
docs/
├── ARCHITECTURE.md        this file
├── CONFIGURATION.md       JSON profile schema reference
└── assets/                README images
```

Every `<tool>.bpf.c`/`<tool>.c` pair is independently buildable and runnable - none of
them import or depend on `nogitsune.c`. `nogitsune` is an orchestrator on top of
already-complete, already-standalone tools, not a runtime dependency they need to
function.
