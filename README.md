<p align="center">
  <img src="docs/assets/logo.png" alt="Nogitsune Logo" width="200"/>
</p>

<h1 align="center">野狐 Nogitsune</h1>

<p align="center">
  <b>eBPF-based anti-sandbox toolkit for Linux malware analysis</b>
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/Linux-5.8%2B-blue.svg" alt="Linux"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License"></a>
  <a href="#"><img src="https://img.shields.io/badge/eBPF-libbpf-orange.svg" alt="eBPF"></a>
</p>

<p align="center">
  <i>Make your VirtualBox VM appear as bare-metal Dell hardware to defeat evasive malware.</i>
</p>

---

## 🦊 What is Nogitsune?

**Nogitsune** is an eBPF-based toolkit that spoofs hardware identifiers at the kernel level, bypassing malware anti-VM/anti-sandbox detection at runtime.

Unlike hypervisor patches requiring QEMU recompilation, Nogitsune works **instantly on stock Linux kernels** (5.8+).

```bash
# Before: Malware detects VirtualBox and exits
$ cat /sys/class/dmi/id/sys_vendor
innotek GmbH

# After: Malware sees Dell hardware and executes
$ sudo nogitsune spoof
[*] Loaded: dmi_spoof, mac_spoof, cpu_spoof, mem_spoof, disk_spoof, proc_hide
[*] VirtualBox -> Dell OptiPlex 7090

$ cat /sys/class/dmi/id/sys_vendor
Dell Inc.
```

---

## ⚡ Quick Start

```bash
# Clone with submodules
git clone --recursive https://github.com/YOUR_USERNAME/nogitsune
cd nogitsune/src

# Build
make

# Run all spoofers
sudo ./nogitsune spoof

# Check what would be spoofed (dry run)
sudo ./nogitsune check

# Hide analysis processes
sudo ./nogitsune hide --name "wireshark,tcpdump,strace"
```

---

## 🎯 What It Defeats

| Detection Technique | File/Method | Status |
|---------------------|-------------|--------|
| **MAC Address** | `/sys/class/net/*/address` | ✅ Spoofed |
| **MAC via ioctl** | `SIOCGIFHWADDR` | ✅ Spoofed |
| **DMI/SMBIOS** | `/sys/class/dmi/id/*` | ✅ Spoofed (10 files) |
| **CPU Info** | `/proc/cpuinfo` | ✅ Spoofed (hypervisor flag removed) |
| **Memory Size** | `/proc/meminfo` | ✅ Spoofed (2GB → 16GB) |
| **Disk Model** | `/sys/class/block/*/device/model` | ✅ Spoofed |
| **PCI Devices** | `/sys/bus/pci/devices/*/vendor` | ✅ Spoofed |
| **Process List** | `getdents64` syscall | ✅ Hidden |
| **Kernel Modules** | `/proc/modules` | ✅ Hidden |
| **CPUID Instruction** | Hardware | ❌ Use KVM `hidden state` |
| **RDTSC Timing** | Hardware | ❌ Use hypervisor patches |

### Spoofed Values (Dell OptiPlex 7090 Profile)

| Field | VirtualBox | Nogitsune |
|-------|------------|-----------|
| `sys_vendor` | innotek GmbH | Dell Inc. |
| `product_name` | VirtualBox | OptiPlex 7090 |
| `bios_vendor` | innotek GmbH | Dell Inc. |
| `board_name` | VirtualBox | 0WN7Y6 |
| `MAC prefix` | 08:00:27 | a4:5e:60 |
| `disk model` | VBOX HARDDISK | Samsung SSD 970 EVO Plus |
| `MemTotal` | 2GB | 16GB |
| `cpu cores` | 2 | 8 |

---

## 🔧 Installation

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt install clang llvm libelf-dev make git

# Fedora
sudo dnf install clang llvm elfutils-libelf-devel make git

# Arch
sudo pacman -S clang llvm libelf make git
```

### Build from Source

```bash
# Clone with submodules (includes libbpf and bpftool)
git clone --recursive https://github.com/YOUR_USERNAME/nogitsune
cd nogitsune/src

# Build everything
make

# Verify
./nogitsune --help
```

### Verify Kernel Support

```bash
# Check kernel version (need 5.8+)
uname -r

# Check BTF support
ls /sys/kernel/btf/vmlinux
```

---

## Usage

### Basic Commands

```bash
# Spoof all hardware identifiers
sudo ./nogitsune spoof

# Spoof specific components only
sudo ./nogitsune spoof --dmi --mac --cpu

# Check current values vs spoofed (dry run)
sudo ./nogitsune check

# Show real system values
sudo ./nogitsune status

# Stop all spoofers (unload eBPF programs)
sudo ./nogitsune stop
```

### Process Hiding

```bash
# Hide by PID
sudo ./nogitsune hide --pid 1234,5678

# Hide by process name
sudo ./nogitsune hide --name "wireshark,tcpdump,strace,gdb"

# Hide self (the nogitsune process)
sudo ./nogitsune hide --self
```

### Running Individual Spoofers

Each spoofer can also run standalone:

```bash
# DMI/SMBIOS only
sudo ./dmi_spoof

# MAC address only  
sudo ./textreplace -f /sys/class/net/eth0/address -i "08:00:27" -r "a4:5e:60"

# CPU info only
sudo ./cpuinfo_spoof

# Memory info only
sudo ./meminfo_spoof

# Process hiding
sudo ./processhide --pid 1234
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Space                              │
│                                                                 │
│  ┌─────────────┐         ┌────────────────────────────────────┐ │
│  │   Malware   │         │         nogitsune CLI              │ │
│  │             │         │                                    │ │
│  │ read() ─────┼────┐    │  • Loads eBPF programs             │ │
│  │ getdents64()│    │    │  • Configures spoof values         │ │
│  └─────────────┘    │    │  • Manages process hiding          │ │
│                     │    └────────────────────────────────────┘ │
├─────────────────────┼───────────────────────────────────────────┤
│                     │        Kernel Space                       │
│                     ▼                                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    eBPF Programs                            ││
│  │                                                             ││
│  │   tracepoint/syscalls/sys_exit_read                         ││
│  │   ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐           ││
│  │   │  MAC    │ │  DMI    │ │  CPU    │ │  MEM    │           ││
│  │   │ Spoof   │ │ Spoof   │ │ Spoof   │ │ Spoof   │           ││
│  │   └─────────┘ └─────────┘ └─────────┘ └─────────┘           ││
│  │                                                             ││
│  │   tracepoint/syscalls/sys_exit_getdents64                   ││
│  │   ┌─────────────┐                                           ││
│  │   │ Process     │  Filters directory entries                ││
│  │   │ Hider       │  to hide PIDs from /proc                  ││
│  │   └─────────────┘                                           ││
│  │                                                             ││
│  │   Hook: bpf_probe_write_user() modifies buffer contents     ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│  Target Files:                                                  │
│  /sys/class/net/*/address    /sys/class/dmi/id/*                │
│  /proc/cpuinfo               /proc/meminfo                      │
│  /sys/class/block/*/device/* /proc/<pid>                        │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Tracepoint Hooks**: Attach to `sys_exit_read` (after kernel fills buffer)
2. **Filename Tracking**: Track which file is being read via `sys_enter_read`  
3. **Content Replacement**: Use `bpf_probe_write_user()` to modify buffer
4. **Process Hiding**: Hook `getdents64` to filter `/proc` directory entries

### Why eBPF?

| Approach | Requires | Runtime | Stealth |
|----------|----------|---------|---------|
| QEMU Patches | Recompilation | Static | High |
| Kernel Module | Custom build | Load/unload | Medium |
| **eBPF** | Stock kernel 5.8+ | Instant | High |

---

## 🔬 For Security Researchers

### Testing Against VMAware

```bash
# Clone and build VMAware
git clone https://github.com/kernelwernel/VMAware
cd VMAware && mkdir build && cd build
cmake .. && make

# Run without Nogitsune
./vmaware

# Run WITH Nogitsune
cd /path/to/nogitsune/src
sudo ./nogitsune spoof &
./vmaware  # Should show fewer detections
```


## References & Credits

### Built On
- [bad-bpf](https://github.com/pathtofile/bad-bpf)
- [VMAware](https://github.com/kernelwernel/VMAware)
- [libbpf](https://github.com/libbpf/libbpf)


## Legal Disclaimer

This tool is for **authorized security research only**:

- ✅ Malware analysis in controlled environments
- ✅ Security testing with proper authorization
- ✅ Educational purposes

**NOT** for:
- ❌ Evading detection on systems you don't own
- ❌ Malicious purposes

The authors are not responsible for misuse.

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

<p align="center">
  <b>Nogitsune</b> - The wild fox that tricks malware<br>
</p>
