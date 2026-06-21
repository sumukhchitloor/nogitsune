# Custom Profile Reference

`nogitsune spoof` and `nogitsune check` accept `-c`/`--config <path>` pointing at a JSON
file. Any key you omit keeps its built-in default (the Dell OptiPlex 7090 profile) - you
only need to specify the fields you want to change.

Quickest way to get started:

```bash
nogitsune init-config my-profile.json   # writes every field at its current default
nogitsune check -c my-profile.json      # preview before applying
sudo nogitsune spoof -c my-profile.json
```

## Schema

```json
{
  "dmi": {
    "sys_vendor": "Dell Inc.",
    "product_name": "OptiPlex 7090",
    "bios_vendor": "Dell Inc.",
    "board_vendor": "Dell Inc.",
    "chassis_vendor": "Dell Inc.",
    "bios_version": "2.15.0",
    "bios_date": "07/14/2023",
    "board_name": "0K240Y",
    "product_family": "OptiPlex",
    "chassis_type": "3",
    "product_version": "1.0",
    "board_version": "1.2"
  },
  "devicetree": {
    "model": "Dell Inc. OptiPlex 7090",
    "compatible": "dell,optiplex-7090"
  },
  "mac": "a4:5e:60:12:34:56",
  "cpu": {
    "cores": 8,
    "microcode": "0x000000b4",
    "keep_hypervisor_flag": false
  },
  "memory": {
    "total_kb": 16384000
  },
  "disk": {
    "model": "Samsung SSD 970"
  },
  "pci": [
    { "from": "0x80ee", "to": "0x8086" },
    { "from": "0xbeef", "to": "0x1234" },
    { "from": "0xcafe", "to": "0x5678" },
    { "from": "0x0021", "to": "0x1000" },
    { "from": "0x0022", "to": "0x1001" }
  ],
  "modules_to_hide": ["vboxguest", "vboxsf", "vboxvideo"],
  "hidden_files": [
    "VBoxGuestAdditions", "vboxadd", "vboxguest.ko", "vboxsf.ko",
    "vboxvideo.ko", "vboxguest", "mount.vboxsf", "VBoxService",
    "VBoxClient", "VBoxControl", "VBoxDRMClient"
  ],
  "hidden_paths": [
    "/usr/sbin/VBoxService", "/usr/bin/VBoxClient",
    "/usr/bin/VBoxControl", "/usr/sbin/mount.vboxsf"
  ],
  "uptime_seconds": 259200,
  "fake_cpu_count": 16
}
```

## Field reference

### `dmi` - DMI/SMBIOS identity (used when `/sys/class/dmi/id` exists)

Applied by `dmi_spoof`. Not used on ARM64 hosts with no DMI (Device Tree boot) - see
`devicetree` below. Max length 30 characters per field (validated by `dmi_spoof`'s own
`--*` flags; longer values are rejected, not silently truncated).

| Key | Type | Default | Maps to flag |
|---|---|---|---|
| `sys_vendor` | string | `"Dell Inc."` | `--sys-vendor` |
| `product_name` | string | `"OptiPlex 7090"` | `--product-name` |
| `bios_vendor` | string | `"Dell Inc."` | `--bios-vendor` |
| `board_vendor` | string | `"Dell Inc."` | `--board-vendor` |
| `chassis_vendor` | string | `"Dell Inc."` | `--chassis-vendor` |
| `bios_version` | string | `"2.15.0"` | `--bios-version` |
| `bios_date` | string | `"07/14/2023"` | `--bios-date` |
| `board_name` | string | `"0K240Y"` | `--board-name` |
| `product_family` | string | `"OptiPlex"` | `--product-family` |
| `chassis_type` | string | `"3"` | `--chassis-type` (numeric code as a string, e.g. `"3"` = desktop) |
| `product_version` | string | `"1.0"` | `--product-version` |
| `board_version` | string | `"1.2"` | `--board-version` |

`modalias`/`uevent` (the combined DMI strings under the same directory) are **not**
configurable - they're fixed-byte-length substring swaps independent of the fields above.

### `devicetree` - ARM64 Device Tree identity (used when there's no DMI)

Applied by `devicetree_spoof` on ARM64 systems that boot via plain Device Tree (Raspberry
Pi, bare QEMU `virt`) instead of UEFI/ACPI. `nogitsune` picks DMI vs Device Tree
automatically based on which path actually exists on the host - you don't choose this
yourself.

| Key | Type | Default | Maps to flag |
|---|---|---|---|
| `model` | string | `"Dell Inc. OptiPlex 7090"` | `--model` |
| `compatible` | string | `"dell,optiplex-7090"` | `--compatible` |

**Known limitation:** real Device Tree `compatible` is a NUL-separated *list* of strings.
This is treated as a single value - adequate to defeat naive string checks, not a
byte-accurate Device Tree compatible list.

### `mac` - MAC address (top-level key, not nested)

One value applied identically across all three MAC-spoofing methods: `ioctl_spoof`
(`SIOCGIFHWADDR`), `netlink_spoof` (`RTM_NEWLINK`), and the sysfs file
(`/sys/class/net/<iface>/address`, via `textreplace`).

| Key | Type | Default |
|---|---|---|
| `mac` | string, format `xx:xx:xx:xx:xx:xx` | `"a4:5e:60:12:34:56"` |

The target interface itself isn't configured here - `nogitsune` auto-detects it (the
first interface observed `up`, excluding `lo`/`docker*`/`veth*`/`br-*`/`virbr*`).

### `cpu` - `/proc/cpuinfo` (x86 only - automatically skipped on ARM64)

Applied by `cpuinfo_spoof`. ARM64 `/proc/cpuinfo` has no `hypervisor` flag or matching
format at all, so this entire section is a no-op there and `cpuinfo_spoof` isn't even
launched.

| Key | Type | Default | Notes |
|---|---|---|---|
| `cores` | integer 1-9 | `8` | **Known limitation:** only a single ASCII digit is ever replaced - multi-digit core counts (10+) aren't supported. Values outside 1-9 are rejected (warning printed, default kept). |
| `microcode` | string, format `0xXXXXXXXX` (8 hex digits) | `"0x000000b4"` | Must be exactly this format - it's a fixed-width swap. |
| `keep_hypervisor_flag` | boolean | `false` | `true` leaves the `hypervisor` flag in `/proc/cpuinfo` instead of blanking it. |

### `memory` - `/proc/meminfo`

Applied by `meminfo_spoof`.

| Key | Type | Default |
|---|---|---|
| `total_kb` | integer, 1-99999999 | `16384000` (~16GB) |

### `disk` - disk model

Applied via two `textreplace` instances (`/sys/block/<disk>/device/model` and
`/sys/class/block/<disk>/device/model`). The target disk is auto-detected (see Known
Limitations in the README) - not configured here.

| Key | Type | Default |
|---|---|---|
| `model` | string | `"Samsung SSD 970"` |

The configured value is automatically padded with trailing spaces or truncated (with a
warning) to match the real file's current length, since `textreplace` requires the
find/replace strings to be exactly the same byte length.

### `pci` - PCI vendor/device ID mappings (array, not an object)

Applied by `pci_spoof`. Replaces the whole array - if you supply `pci` at all, it replaces
**all 5 defaults**, not just adds to them. Max 8 entries.

| Key | Type | Format |
|---|---|---|
| `from` | string | `0x` + exactly 4 hex digits, e.g. `"0x80ee"` |
| `to` | string | `0x` + exactly 4 hex digits, e.g. `"0x8086"` |

### `modules_to_hide` - kernel modules to hide from `/proc/modules` (array of strings)

Applied by `modules_hide`, only when the `modules` spoofer is enabled (off by default -
pass `--modules` to `spoof`, or it has no effect even if configured here). Max 8 entries,
each up to 30 characters.

| Key | Type | Default |
|---|---|---|
| `modules_to_hide` | array of strings | `["vboxguest", "vboxsf", "vboxvideo"]` |

### `hidden_files` - filename prefixes hidden from directory listings (array of strings)

Applied by `fshide` (part of `--artifacts`). Hides any directory entry whose name *starts
with* a configured string from `ls`/`find`/`readdir` system-wide, by hooking `getdents64`
(the same technique `pidhide` uses for `/proc` PID entries, generalized to arbitrary
filenames). Prefix matching is intentional - it's what lets one entry
(`"VBoxGuestAdditions"`) match a version-suffixed real directory
(`VBoxGuestAdditions-7.2.2`) without needing the exact version. Max 16 entries, 31
characters each.

**Known limitation:** this only defeats *enumeration*. A caller that already knows the
exact path doesn't need to list the directory, and bypasses this entirely - see
`hidden_paths`/`pathdeny` below for that gap.

| Key | Type | Default |
|---|---|---|
| `hidden_files` | array of strings (prefix match) | `["VBoxGuestAdditions", "vboxadd", "vboxguest.ko", "vboxsf.ko", "vboxvideo.ko", "vboxguest", "mount.vboxsf", "VBoxService", "VBoxClient", "VBoxControl", "VBoxDRMClient"]` |

### `hidden_paths` - exact paths denied on open/stat/access (array of strings)

Applied by `pathdeny` (part of `--artifacts`), using BPF LSM to deny `open()`/`stat()`/
`access()` on configured paths with ENOENT - closes the gap `hidden_files` can't (direct
probing of a known path). Requires `CONFIG_BPF_LSM` + `bpf` active in
`/sys/kernel/security/lsm`; if unavailable, `pathdeny` exits cleanly without affecting any
other spoofer (see Known Limitations). Unlike `hidden_files`, these must be **exact**
paths, not prefixes - a versioned directory like `/opt/VBoxGuestAdditions-7.2.2` won't
generalize across installs the way `hidden_files`' prefix matching does, which is why the
defaults here are all version-independent binary paths instead. Max 8 entries, 79
characters each.

**Known limitation:** `access()` coverage (specifically) only applies to paths that
already existed when `pathdeny` started - it resolves each path's `(device, inode)` once
at startup, since the kernel hook for `access()` has no path string available at all
(confirmed by direct kernel BTF inspection - only `open()`/`stat()` coverage gets a real
path string to match against, and those two work dynamically regardless of when the path
appeared).

| Key | Type | Default |
|---|---|---|
| `hidden_paths` | array of strings (exact match) | `["/usr/sbin/VBoxService", "/usr/bin/VBoxClient", "/usr/bin/VBoxControl", "/usr/sbin/mount.vboxsf"]` |

### `uptime_seconds` - `/proc/uptime` (top-level key, not nested)

Applied by `uptime_spoof` (part of `--uptime`). Defeats the "suspiciously fresh boot"
heuristic.

**Known limitation:** this is a static value, not a ticking clock - reading it twice with
a real delay between reads returns the same frozen number both times, which is itself a
(less common) tell.

| Key | Type | Default |
|---|---|---|
| `uptime_seconds` | integer, 1 to ~3.15 billion | `259200` (3 days) |

### `fake_cpu_count` - `sched_getaffinity()` CPU count (top-level key, not nested)

Applied by `cpucount_spoof` (part of `--cpucount`). Inflates the CPU count callers like
`nproc` see (`nproc`'s *default* behavior calls `sched_getaffinity`, not `/proc/cpuinfo`).
If set below the real online CPU count, `cpucount_spoof` clamps it *up* to the real count
instead of erroring - making the host look like it has fewer CPUs than it really does
isn't a useful failure mode.

**Known limitation:** covers `sched_getaffinity()` only. `/sys/devices/system/cpu/*` and
`/proc/cpuinfo`'s processor-line count (what `nproc --all` uses, and the only thing ARM64
even has) are separate, unaddressed code paths - confirmed independent by code inspection,
not assumed.

| Key | Type | Default |
|---|---|---|
| `fake_cpu_count` | integer, 1-256 | `16` |

## Notes

- Invalid JSON or an unreadable file prints an error and falls back to defaults - it
  never silently applies a half-parsed profile.
- Keys not listed above are ignored (not an error) - useful if you want to keep notes or
  metadata in the same file.
- Every individual spoofer binary also accepts its own flags directly if you want to run
  one standalone without `nogitsune` at all (e.g. `./dmi_spoof --sys-vendor "Lenovo"`) -
  run any of them with `--help` for the exact flag names, which match the JSON keys above
  one-to-one.
