/*
 * Nogitsune - eBPF Anti-Sandbox Toolkit
 * Unified CLI for loading and managing spoofers
 *
 * Usage:
 *   nogitsune spoof [--dmi] [--mac] [--cpu] [--mem] [--stealth] [--background] [-c config.json]
 *   nogitsune check [-c config.json]
 *   nogitsune status
 *   nogitsune stop
 *   nogitsune hide --pid <pids> | --name <names>
 *   nogitsune init-config [path]
 *
 * Run 'nogitsune <command> --help' for command-specific options.
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <signal.h>
 #include <sys/wait.h>
 #include <sys/stat.h>
 #include <sys/utsname.h>
 #include <fcntl.h>
 #include <errno.h>
 #include <stdbool.h>
 #include <dirent.h>
 #include <time.h>
 #include "cJSON.h"

 #define VERSION "1.0.0"
 #define PROGNAME "nogitsune"

 /* Colors for terminal output */
 #define RED     "\x1b[31m"
 #define GREEN   "\x1b[32m"
 #define YELLOW  "\x1b[33m"
 #define BLUE    "\x1b[34m"
 #define MAGENTA "\x1b[35m"
 #define CYAN    "\x1b[36m"
 #define WHITE   "\x1b[37m"
 #define RESET   "\x1b[0m"
 #define BOLD    "\x1b[1m"
 #define DIM     "\x1b[2m"

 /* Bright colors */
 #define BRED    "\x1b[91m"
 #define BGREEN  "\x1b[92m"
 #define BYELLOW "\x1b[93m"
 #define BBLUE   "\x1b[94m"
 #define BMAGENTA "\x1b[95m"
 #define BCYAN   "\x1b[96m"
 #define BWHITE  "\x1b[97m"

 /* Built-in default profile - Dell OptiPlex 7090 */
 #define DELL_MAC_FULL    "a4:5e:60:12:34:56"
 #define DELL_MAC_OUI     "a4:5e:60"
 #define VBOX_MAC_OUI     "08:00:27"

 #define MAX_PCI_MAPPINGS 8
 #define MAX_MODULES_TO_HIDE 8
 #define MAX_HIDDEN_FILES 16
 #define MAX_HIDDEN_PATHS 8

 /* Tracks the running spoof session across separate CLI invocations, so
  * "nogitsune stop" works from a different terminal/process than the one
  * that ran "spoof", and so "spoof" can refuse to start a second
  * concurrent session. */
 #define NOGITSUNE_PIDFILE "/run/nogitsune.pid"
 #define NOGITSUNE_LOGFILE "/var/log/nogitsune.log"

 /* Spoofer types */
 typedef enum {
     SPOOF_TYPE_BPF,        /* eBPF binary */
     SPOOF_TYPE_TEXTREPLACE /* textreplace with dynamically-built args */
 } spoof_type_t;

 /* Spoofer definitions */
 typedef struct {
     const char *name;
     const char *binary;
     const char *args;         /* unused, kept for struct-layout stability */
     const char *description;
     const char *target;
     spoof_type_t type;
     bool enabled;
     pid_t pid;
 } spoofer_t;

 /*
  * Global spoofer list
  * Order matters - some may depend on others.
  *
  * "hwid"'s binary/description/target are mutated at runtime in cmd_spoof()
  * once hardware identity (DMI vs Device Tree) is detected - see
  * detect_hw_identity().
  */
 static spoofer_t spoofers[] = {
     {"hwid",            "./dmi_spoof",   NULL,
      "DMI/SMBIOS spoofing (12 files)",   "/sys/class/dmi/id/*",
      SPOOF_TYPE_BPF, true, 0},

     {"cpu",             "./cpuinfo_spoof", NULL,
      "CPU info spoofing",                "/proc/cpuinfo",
      SPOOF_TYPE_BPF, true, 0},

     {"mem",             "./meminfo_spoof", NULL,
      "Memory info spoofing",             "/proc/meminfo",
      SPOOF_TYPE_BPF, true, 0},

     {"pci",             "./pci_spoof",   NULL,
      "PCI device ID spoofing",           "/sys/bus/pci/devices/*/vendor",
      SPOOF_TYPE_BPF, true, 0},

     /* MAC Address - THREE methods for full coverage */
     {"mac-ioctl",       "./ioctl_spoof", NULL,
      "MAC via ioctl (SIOCGIFHWADDR)",    "ioctl syscall",
      SPOOF_TYPE_BPF, true, 0},

     {"mac-netlink",     "./netlink_spoof", NULL,
      "MAC via netlink (RTM_GETLINK)",    "netlink socket",
      SPOOF_TYPE_BPF, true, 0},

     {"mac-file",        "./textreplace", NULL,
      "MAC via file read",                "/sys/class/net/*/address",
      SPOOF_TYPE_TEXTREPLACE, true, 0},

     /* Disk - two locations report the same model file */
     {"disk-sysblock",   "./textreplace", NULL,
      "Disk model spoofing",              "/sys/block/*/device/model",
      SPOOF_TYPE_TEXTREPLACE, true, 0},

     {"disk-classblock", "./textreplace", NULL,
      "Disk model spoofing",              "/sys/class/block/*/device/model",
      SPOOF_TYPE_TEXTREPLACE, true, 0},

     /* Kernel modules - Hide vbox modules (optional) */
     {"modules",         "./modules_hide", NULL,
      "Kernel module hiding",             "/proc/modules",
      SPOOF_TYPE_BPF, false, 0},  /* Disabled by default */

     /* Guest-Additions artifact hiding - directory-listing (fshide) and
      * direct-path (pathdeny) coverage are complementary, grouped under
      * --artifacts as one unit (see cmd_spoof). */
     {"artifacts-fshide",   "./fshide",   NULL,
      "Hide Guest Additions artifacts from directory listings", "ls/find enumeration",
      SPOOF_TYPE_BPF, true, 0},

     {"artifacts-pathdeny", "./pathdeny", NULL,
      "Deny direct open/stat/access on Guest Additions paths",  "BPF LSM",
      SPOOF_TYPE_BPF, true, 0},

     {"uptime",          "./uptime_spoof",   NULL,
      "Uptime spoofing",                  "/proc/uptime",
      SPOOF_TYPE_BPF, true, 0},

     {"cpucount",        "./cpucount_spoof", NULL,
      "CPU affinity count spoofing",      "sched_getaffinity",
      SPOOF_TYPE_BPF, true, 0},

     {"kmsg",            "./kmsg_spoof",     NULL,
      "Live kernel-log sanitization",     "/dev/kmsg, syslog()",
      SPOOF_TYPE_BPF, true, 0},

     {NULL, NULL, NULL, NULL, NULL, SPOOF_TYPE_BPF, false, 0}
 };

 /* ========================================================================== */
 /* RUNTIME-CONFIGURABLE PROFILE                                              */
 /* ========================================================================== */

 struct pci_mapping {
     char from[7]; /* "0xXXXX" + NUL */
     char to[7];
 };

 struct nogitsune_profile {
     /* DMI/SMBIOS (used when /sys/class/dmi/id exists) */
     char dmi_sys_vendor[32];
     char dmi_product_name[32];
     char dmi_bios_vendor[32];
     char dmi_board_vendor[32];
     char dmi_chassis_vendor[32];
     char dmi_bios_version[32];
     char dmi_bios_date[32];
     char dmi_board_name[32];
     char dmi_product_family[32];
     char dmi_chassis_type[32];
     char dmi_product_version[32];
     char dmi_board_version[32];

     /* Device Tree (used on ARM64 hosts with no DMI - see detect_hw_identity) */
     char devicetree_model[64];
     char devicetree_compatible[64];

     /* MAC - shared by all three MAC spoofing methods */
     char mac[18];

     /* CPU */
     char cpu_cores; /* single ASCII digit '1'-'9' */
     char cpu_microcode[11];
     bool cpu_keep_hypervisor_flag;

     /* Memory */
     unsigned int mem_total_kb;

     /* Disk */
     char disk_model[32];

     /* PCI vendor/device ID mappings */
     struct pci_mapping pci_mappings[MAX_PCI_MAPPINGS];
     int num_pci_mappings;

     /* Kernel modules to hide (only used if "modules" spoofer is enabled) */
     char modules_to_hide[MAX_MODULES_TO_HIDE][32];
     int num_modules_to_hide;

     /* Filename prefixes to hide from directory listings (fshide) */
     char hidden_files[MAX_HIDDEN_FILES][32];
     int num_hidden_files;

     /* Exact paths to deny open/stat/access on (pathdeny) */
     char hidden_paths[MAX_HIDDEN_PATHS][80];
     int num_hidden_paths;

     /* Spoofed /proc/uptime value, in seconds */
     unsigned int uptime_seconds;

     /* Spoofed sched_getaffinity() CPU count */
     unsigned int fake_cpu_count;
 };

 typedef enum {
     HW_IDENTITY_DMI,
     HW_IDENTITY_DEVICETREE,
     HW_IDENTITY_NONE,
 } hw_identity_t;

/* Global state */
static pid_t g_pidhide_pid = 0;
static char g_exe_dir[512] = ".";

 /* Forward declarations */
 static void print_banner(void);
 static void print_banner_small(void);
 static void print_usage(void);
 static int cmd_spoof(int argc, char **argv);
 static int cmd_check(int argc, char **argv);
 static int cmd_status(int argc, char **argv);
 static int cmd_stop(int argc, char **argv);
 static int cmd_hide(int argc, char **argv);
 static int cmd_init_config(int argc, char **argv);
 static bool check_root(void);
 static bool file_exists(const char *path);
 static char *read_file_line(const char *path);
 static int launch_pidhide_stealth(void);
 static int launch_spoofer(spoofer_t *spoofer, const struct nogitsune_profile *profile,
                           const char *disk, const char *iface);
 static void init_default_profile(struct nogitsune_profile *p);
 static bool load_profile(int argc, char **argv, struct nogitsune_profile *p);
 static cJSON *profile_to_json(const struct nogitsune_profile *p);
 static hw_identity_t detect_hw_identity(void);
 static bool detect_primary_disk(char *out, size_t out_size);
 static bool detect_primary_iface(char *out, size_t out_size);
 static void pad_or_truncate(char *out, size_t out_size, const char *src, size_t target_len);
 static const char *get_arch_string(void);
 static bool args_have_help(int argc, char **argv);
 static bool write_pidfile(pid_t pid);
 static pid_t read_pidfile(void);
 static bool pid_is_running(pid_t pid);
 static pid_t daemonize_into_background(void);
 static void print_spoof_help(void);
 static void print_check_help(void);
 static void print_status_help(void);
 static void print_stop_help(void);
 static void print_hide_help(void);
 static void print_initconfig_help(void);

 /* ========================================================================== */
 /* KICKASS ASCII BANNER                                                       */
 /* ========================================================================== */

 static void print_banner(void)
 {
     printf("\n");
     printf(BRED "    ███╗   ██╗ ██████╗  ██████╗ ██╗████████╗███████╗██╗   ██╗███╗   ██╗███████╗\n" RESET);
     printf(BRED "    ████╗  ██║██╔═══██╗██╔════╝ ██║╚══██╔══╝██╔════╝██║   ██║████╗  ██║██╔════╝\n" RESET);
     printf(BYELLOW "    ██╔██╗ ██║██║   ██║██║  ███╗██║   ██║   ███████╗██║   ██║██╔██╗ ██║█████╗  \n" RESET);
     printf(BYELLOW "    ██║╚██╗██║██║   ██║██║   ██║██║   ██║   ╚════██║██║   ██║██║╚██╗██║██╔══╝  \n" RESET);
     printf(BWHITE "    ██║ ╚████║╚██████╔╝╚██████╔╝██║   ██║   ███████║╚██████╔╝██║ ╚████║███████╗\n" RESET);
     printf(BWHITE "    ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝\n" RESET);
     printf("\n");
     printf(DIM "                        ╭──────────────────────────────────╮\n" RESET);
     printf(DIM "                        │" RESET BOLD "  野狐 " RESET CYAN "eBPF Anti-Sandbox Toolkit" DIM "     │\n" RESET);
     printf(DIM "                        │" RESET "     Make VMs Look Like Metal     " DIM "│\n" RESET);
     printf(DIM "                        ╰──────────────────────────────────╯\n" RESET);
     printf("\n");
 }

 static void print_banner_small(void)
 {
     printf("\n");
     printf(BYELLOW "  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n" RESET);
     printf(BYELLOW "  ┃" RESET BOLD " 野狐 " BRED "NOGITSUNE" RESET " ━ eBPF Anti-Sandbox Toolkit        " BYELLOW "   ┃\n" RESET);
     printf(BYELLOW "  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n" RESET);
     printf("\n");
 }

 /* ========================================================================== */

 static void print_usage(void)
 {
     print_banner();

     const char *arch = get_arch_string();
     printf("    " DIM "v%s  ·  running on %s  ·  " RESET, VERSION, arch);
     pid_t session_pid = read_pidfile();
     if (pid_is_running(session_pid)) {
         printf(BGREEN "session active (PID %d)\n" RESET, session_pid);
     } else {
         printf(DIM "no active session\n" RESET);
     }
     printf("\n");

     printf(BOLD "USAGE:" RESET "\n");
     printf("    " CYAN "%s" RESET " <command> [options]\n\n", PROGNAME);

     printf(BOLD BYELLOW "CORE COMMANDS:\n" RESET);
     printf("    " BGREEN "init-config" RESET " [path]   Write a starter JSON profile you can edit (no root)\n");
     printf("    " BGREEN "check" RESET "             Dry run - preview what 'spoof' would change (no root)\n");
     printf("    " BGREEN "spoof" RESET "             Load spoofers - make this VM look like real hardware\n");
     printf("    " BGREEN "status" RESET "            Scan for VM indicators + show session state\n");
     printf("    " BGREEN "stop" RESET "              Stop the running spoof session\n");
     printf("    " BGREEN "hide" RESET "              Hide specific processes from /proc (standalone)\n");
     printf("\n");

     printf(BOLD BYELLOW "GETTING STARTED:\n" RESET);
     printf(DIM "    1. Try it with the built-in Dell profile:\n" RESET);
     printf("       " WHITE "$ sudo %s spoof --stealth\n" RESET, PROGNAME);
     printf(DIM "    2. Or use your own hardware profile:\n" RESET);
     printf("       " WHITE "$ %s init-config my-profile.json\n" RESET, PROGNAME);
     printf("       " WHITE "$ %s check -c my-profile.json" RESET DIM "        # preview it\n" RESET, PROGNAME);
     printf("       " WHITE "$ sudo %s spoof -c my-profile.json --background\n" RESET, PROGNAME);
     printf("\n");

     printf(BOLD BYELLOW "KEY FLAGS (spoof):\n" RESET);
     printf("    " BCYAN "-c, --config PATH" RESET "   Use a custom JSON profile instead of built-in defaults\n");
     printf("    " BCYAN "-d, --background" RESET "    Detach and keep running after this shell exits\n");
     printf("    " BCYAN "--stealth" RESET "           " BRED "★" RESET " Also hide spoofer processes from ps/top\n");
     printf("    --dmi/--mac/--cpu/--mem/--pci/--disk/--modules/--artifacts/--uptime/--cpucount/--kmsg\n");
     printf("                         Load only specific spoofers\n");
     printf("\n");

     printf(BOLD BYELLOW "EXAMPLES:\n" RESET);
     printf(DIM "    # Full stealth mode, detached so closing this shell doesn't stop it\n" RESET);
     printf("    " WHITE "$ sudo %s spoof --stealth --background\n" RESET, PROGNAME);
     printf("\n");
     printf(DIM "    # Check for VM indicators, then stop a backgrounded session later\n" RESET);
     printf("    " WHITE "$ sudo %s status\n" RESET, PROGNAME);
     printf("    " WHITE "$ sudo %s stop\n" RESET, PROGNAME);
     printf("\n");
     printf(DIM "    # Hide analysis tools from malware (independent of 'spoof')\n" RESET);
     printf("    " WHITE "$ sudo %s hide --name wireshark,tcpdump,gdb,strace\n" RESET, PROGNAME);
     printf("\n");

     printf(BOLD "Run " RESET CYAN "%s <command> --help" RESET BOLD " for that command's full options.\n" RESET, PROGNAME);
     printf(BOLD "Full custom-profile field reference: " RESET CYAN "docs/CONFIGURATION.md" RESET "\n");
     printf("\n");
 }

 static bool check_root(void)
 {
     if (geteuid() != 0) {
         fprintf(stderr, RED "  [" BRED "✗" RED "] " RESET "Must run as root (need CAP_BPF)\n");
         fprintf(stderr, "      " DIM "Try: sudo %s <command>\n" RESET, PROGNAME);
         return false;
     }
     return true;
 }

 static bool file_exists(const char *path)
 {
     struct stat st;
     return stat(path, &st) == 0;
 }

 static char *read_file_line(const char *path)
 {
     static char buf[256];
     FILE *f = fopen(path, "r");
     if (!f) return NULL;

     if (fgets(buf, sizeof(buf), f) == NULL) {
         fclose(f);
         return NULL;
     }
     fclose(f);

     /* Remove trailing newline */
     size_t len = strlen(buf);
     if (len > 0 && buf[len-1] == '\n')
         buf[len-1] = '\0';

     return buf;
 }

 static bool is_vbox_string(const char *str)
 {
     if (!str) return false;
     return (strstr(str, "VirtualBox") != NULL ||
             strstr(str, "vbox") != NULL ||
             strstr(str, "VBOX") != NULL ||
             strstr(str, "innotek") != NULL ||
             strstr(str, "Oracle") != NULL ||
             strncmp(str, "08:00:27", 8) == 0);
 }

 /* ========================================================================== */
 /* HARDWARE IDENTITY / DISK / NIC DETECTION                                  */
 /* ========================================================================== */

 /* DMI/SMBIOS is a UEFI/ACPI firmware feature, not an x86-specific one - ARM64
  * VMs booted with UEFI firmware (QEMU ArmVirt/EDK2, many cloud ARM64 VMs)
  * expose /sys/class/dmi/id too. ARM64 systems booted via plain Device Tree
  * (Raspberry Pi, bare QEMU 'virt') have no DMI at all and need
  * /proc/device-tree instead. Detect by checking which path actually
  * exists, not by checking CPU architecture. */
 static hw_identity_t detect_hw_identity(void)
 {
     if (file_exists("/sys/class/dmi/id/sys_vendor"))
         return HW_IDENTITY_DMI;
     if (file_exists("/proc/device-tree/model") || file_exists("/proc/device-tree/compatible"))
         return HW_IDENTITY_DEVICETREE;
     return HW_IDENTITY_NONE;
 }

 /* Heuristic, NOT real root-filesystem resolution: picks the
  * lexicographically-first /sys/block entry that has a device/model file,
  * excluding loop/ram/zram/sr devices (so "sda" < "sdb", "vda" < "vdb",
  * "nvme0n1" < "nvme1n1"). This can pick the wrong disk on a system where a
  * secondary/data drive enumerates before the boot/root drive - documented
  * limitation, see README. Returns false (out left unset) if nothing found. */
 static bool detect_primary_disk(char *out, size_t out_size)
 {
     DIR *d = opendir("/sys/block");
     if (!d)
         return false;

     char best[64] = "";
     struct dirent *entry;
     while ((entry = readdir(d)) != NULL) {
         const char *name = entry->d_name;
         if (name[0] == '.') continue;
         if (strncmp(name, "loop", 4) == 0) continue;
         if (strncmp(name, "ram", 3) == 0) continue;
         if (strncmp(name, "zram", 4) == 0) continue;
         if (strncmp(name, "sr", 2) == 0) continue;

         char model_path[300];
         snprintf(model_path, sizeof(model_path), "/sys/block/%s/device/model", name);
         if (!file_exists(model_path)) continue;

         if (best[0] == '\0' || strcmp(name, best) < 0) {
             strncpy(best, name, sizeof(best) - 1);
         }
     }
     closedir(d);

     if (best[0] == '\0')
         return false;
     strncpy(out, best, out_size - 1);
     out[out_size - 1] = '\0';
     return true;
 }

 /* Heuristic, NOT authoritative: prefers the first non-excluded interface
  * (lexicographically) whose operstate is "up". If no interface is
  * observed up at detection time (e.g. spoofing launched before a NIC
  * comes up at boot), falls back to the first non-excluded interface in
  * lexicographic order regardless of state and warns that the pick is
  * unconfirmed - documented limitation, see README. Returns false (out
  * left unset) only if there are no candidate interfaces at all. */
 static bool detect_primary_iface(char *out, size_t out_size)
 {
     DIR *d = opendir("/sys/class/net");
     if (!d)
         return false;

     char up_candidate[64] = "";
     char any_candidate[64] = "";
     struct dirent *entry;
     while ((entry = readdir(d)) != NULL) {
         const char *name = entry->d_name;
         if (name[0] == '.') continue;
         if (strcmp(name, "lo") == 0) continue;
         if (strncmp(name, "docker", 6) == 0) continue;
         if (strncmp(name, "veth", 4) == 0) continue;
         if (strncmp(name, "br-", 3) == 0) continue;
         if (strncmp(name, "virbr", 5) == 0) continue;

         if (any_candidate[0] == '\0' || strcmp(name, any_candidate) < 0) {
             strncpy(any_candidate, name, sizeof(any_candidate) - 1);
         }

         char operstate_path[300];
         snprintf(operstate_path, sizeof(operstate_path), "/sys/class/net/%s/operstate", name);
         char *state = read_file_line(operstate_path);
         if (state && strcmp(state, "up") == 0) {
             if (up_candidate[0] == '\0' || strcmp(name, up_candidate) < 0) {
                 strncpy(up_candidate, name, sizeof(up_candidate) - 1);
             }
         }
     }
     closedir(d);

     if (up_candidate[0] != '\0') {
         strncpy(out, up_candidate, out_size - 1);
         out[out_size - 1] = '\0';
         return true;
     }
     if (any_candidate[0] != '\0') {
         fprintf(stderr, YELLOW "  [!] No interface observed 'up' at detection time - "
                          "falling back to '%s' (unconfirmed)\n" RESET, any_candidate);
         strncpy(out, any_candidate, out_size - 1);
         out[out_size - 1] = '\0';
         return true;
     }
     return false;
 }

 /* textreplace requires its find/replace strings to be exactly the same
  * byte length. Pads `src` with spaces or truncates it to exactly
  * `target_len` bytes (warning if truncating), instead of assuming the
  * real file's current value is always a fixed length. */
 static void pad_or_truncate(char *out, size_t out_size, const char *src, size_t target_len)
 {
     if (target_len >= out_size)
         target_len = out_size - 1;
     size_t src_len = strlen(src);
     if (src_len > target_len) {
         fprintf(stderr, YELLOW "  [!] Truncating '%s' to %zu chars to match real file length\n" RESET,
                 src, target_len);
         memcpy(out, src, target_len);
     } else {
         memcpy(out, src, src_len);
         memset(out + src_len, ' ', target_len - src_len);
     }
     out[target_len] = '\0';
 }

 /* ========================================================================== */
 /* ARCHITECTURE / HELP-ARG / SESSION (PID FILE) / BACKGROUND MODE HELPERS    */
 /* ========================================================================== */

 static const char *get_arch_string(void)
 {
     static struct utsname uts;
     if (uname(&uts) == 0)
         return uts.machine;
     return "unknown";
 }

 /* True if -h/--help appears anywhere in this command's remaining args. */
 static bool args_have_help(int argc, char **argv)
 {
     for (int i = 0; i < argc; i++) {
         if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)
             return true;
     }
     return false;
 }

 static bool write_pidfile(pid_t pid)
 {
     FILE *f = fopen(NOGITSUNE_PIDFILE, "w");
     if (!f)
         return false;
     fprintf(f, "%d\n", pid);
     fclose(f);
     return true;
 }

 /* Returns -1 if the file is missing or unreadable. */
 static pid_t read_pidfile(void)
 {
     FILE *f = fopen(NOGITSUNE_PIDFILE, "r");
     if (!f)
         return -1;
     int pid = -1;
     if (fscanf(f, "%d", &pid) != 1)
         pid = -1;
     fclose(f);
     return (pid_t)pid;
 }

 static bool pid_is_running(pid_t pid)
 {
     if (pid <= 0)
         return false;
     return kill(pid, 0) == 0;
 }

 /* Detaches the calling process into the background: single fork + setsid,
  * stdio redirected to NOGITSUNE_LOGFILE (stdin to /dev/null). The caller
  * (parent) gets the child's PID back and should print it and return
  * immediately; the child returns true and continues running the normal
  * spoof logic with output now going to the log file instead of the
  * terminal. Returns -1 on fork failure, the child PID in the parent, or 0
  * in the child (mirroring fork()'s own return convention so callers can
  * branch on it the same way). */
 static pid_t daemonize_into_background(void)
 {
     pid_t pid = fork();
     if (pid != 0)
         return pid; /* parent (pid > 0) or fork failure (pid < 0) */

     /* Child: detach from the controlling terminal/session */
     if (setsid() < 0) {
         _exit(1);
     }
     signal(SIGHUP, SIG_IGN);

     int devnull = open("/dev/null", O_RDWR);
     if (devnull >= 0) {
         dup2(devnull, STDIN_FILENO);
         close(devnull);
     }

     int logfd = open(NOGITSUNE_LOGFILE, O_CREAT | O_WRONLY | O_APPEND, 0644);
     if (logfd >= 0) {
         dup2(logfd, STDOUT_FILENO);
         dup2(logfd, STDERR_FILENO);
         close(logfd);
     } else {
         /* Can't open the log file - fall back to /dev/null rather than
          * leaving stdout/stderr attached to a terminal we just detached
          * from (writes would just fail/SIGPIPE). */
         int dn2 = open("/dev/null", O_WRONLY);
         if (dn2 >= 0) {
             dup2(dn2, STDOUT_FILENO);
             dup2(dn2, STDERR_FILENO);
             close(dn2);
         }
     }

     return 0;
 }

 /* ========================================================================== */
 /* PROFILE LOADING (defaults + optional JSON override)                       */
 /* ========================================================================== */

 static void init_default_profile(struct nogitsune_profile *p)
 {
     memset(p, 0, sizeof(*p));

     strncpy(p->dmi_sys_vendor, "Dell Inc.", sizeof(p->dmi_sys_vendor) - 1);
     strncpy(p->dmi_product_name, "OptiPlex 7090", sizeof(p->dmi_product_name) - 1);
     strncpy(p->dmi_bios_vendor, "Dell Inc.", sizeof(p->dmi_bios_vendor) - 1);
     strncpy(p->dmi_board_vendor, "Dell Inc.", sizeof(p->dmi_board_vendor) - 1);
     strncpy(p->dmi_chassis_vendor, "Dell Inc.", sizeof(p->dmi_chassis_vendor) - 1);
     strncpy(p->dmi_bios_version, "2.15.0", sizeof(p->dmi_bios_version) - 1);
     strncpy(p->dmi_bios_date, "07/14/2023", sizeof(p->dmi_bios_date) - 1);
     strncpy(p->dmi_board_name, "0K240Y", sizeof(p->dmi_board_name) - 1);
     strncpy(p->dmi_product_family, "OptiPlex", sizeof(p->dmi_product_family) - 1);
     strncpy(p->dmi_chassis_type, "3", sizeof(p->dmi_chassis_type) - 1);
     strncpy(p->dmi_product_version, "1.0", sizeof(p->dmi_product_version) - 1);
     strncpy(p->dmi_board_version, "1.2", sizeof(p->dmi_board_version) - 1);

     strncpy(p->devicetree_model, "Dell Inc. OptiPlex 7090", sizeof(p->devicetree_model) - 1);
     strncpy(p->devicetree_compatible, "dell,optiplex-7090", sizeof(p->devicetree_compatible) - 1);

     snprintf(p->mac, sizeof(p->mac), "%s", DELL_MAC_FULL);

     p->cpu_cores = '8';
     snprintf(p->cpu_microcode, sizeof(p->cpu_microcode), "%s", "0x000000b4");
     p->cpu_keep_hypervisor_flag = false;

     p->mem_total_kb = 16384000;

     strncpy(p->disk_model, "Samsung SSD 970", sizeof(p->disk_model) - 1);

     static const struct pci_mapping defaults[] = {
         {"0x80ee", "0x8086"},
         {"0xbeef", "0x1234"},
         {"0xcafe", "0x5678"},
         {"0x0021", "0x1000"},
         {"0x0022", "0x1001"},
     };
     p->num_pci_mappings = sizeof(defaults) / sizeof(defaults[0]);
     memcpy(p->pci_mappings, defaults, sizeof(defaults));

     static const char *def_modules[] = {"vboxguest", "vboxsf", "vboxvideo"};
     p->num_modules_to_hide = 3;
     for (int i = 0; i < 3; i++)
         strncpy(p->modules_to_hide[i], def_modules[i], sizeof(p->modules_to_hide[i]) - 1);

     /* Confirmed-present VirtualBox Guest Additions artifacts (see fshide.c
      * for where this same list lives as that tool's own standalone
      * default - kept in sync manually, not shared via a common header,
      * consistent with how dmi_spoof's profile and modules_hide's profile
      * each separately mirror their own tool's defaults). */
     static const char *def_hidden_files[] = {
         "VBoxGuestAdditions", "vboxadd", "vboxguest.ko", "vboxsf.ko",
         "vboxvideo.ko", "vboxguest", "mount.vboxsf", "VBoxService",
         "VBoxClient", "VBoxControl", "VBoxDRMClient",
     };
     p->num_hidden_files = sizeof(def_hidden_files) / sizeof(def_hidden_files[0]);
     for (int i = 0; i < p->num_hidden_files; i++)
         strncpy(p->hidden_files[i], def_hidden_files[i], sizeof(p->hidden_files[i]) - 1);

     /* Only version-independent paths (unlike the /opt/VBoxGuestAdditions-X.Y.Z
      * directory, which fshide's prefix match already handles - pathdeny
      * needs exact paths, so a version-suffixed default wouldn't generalize
      * across installs). */
     static const char *def_hidden_paths[] = {
         "/usr/sbin/VBoxService", "/usr/bin/VBoxClient",
         "/usr/bin/VBoxControl", "/usr/sbin/mount.vboxsf",
     };
     p->num_hidden_paths = sizeof(def_hidden_paths) / sizeof(def_hidden_paths[0]);
     for (int i = 0; i < p->num_hidden_paths; i++)
         strncpy(p->hidden_paths[i], def_hidden_paths[i], sizeof(p->hidden_paths[i]) - 1);

     p->uptime_seconds = 259200; /* 3 days */
     p->fake_cpu_count = 16;
 }

 static void json_get_string(cJSON *obj, const char *key, char *dst, size_t dst_size)
 {
     if (!obj) return;
     cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
     if (item && cJSON_IsString(item) && item->valuestring) {
         strncpy(dst, item->valuestring, dst_size - 1);
         dst[dst_size - 1] = '\0';
     }
 }

 static bool json_get_uint(cJSON *obj, const char *key, unsigned int *dst)
 {
     if (!obj) return false;
     cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
     if (item && cJSON_IsNumber(item)) {
         *dst = (unsigned int)item->valuedouble;
         return true;
     }
     return false;
 }

 static bool json_get_bool(cJSON *obj, const char *key, bool *dst)
 {
     if (!obj) return false;
     cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
     if (item && cJSON_IsBool(item)) {
         *dst = cJSON_IsTrue(item) ? true : false;
         return true;
     }
     return false;
 }

 /* Parses the JSON config and overlays present keys onto `p` (already
  * holding defaults) - absent keys naturally keep their default. */
 static bool load_profile_from_json(const char *path, struct nogitsune_profile *p)
 {
     FILE *f = fopen(path, "r");
     if (!f) {
         fprintf(stderr, RED "  [!] Cannot open config file: %s\n" RESET, path);
         return false;
     }

     fseek(f, 0, SEEK_END);
     long size = ftell(f);
     fseek(f, 0, SEEK_SET);
     if (size <= 0 || size > 1024 * 1024) {
         fprintf(stderr, RED "  [!] Config file invalid or too large: %s\n" RESET, path);
         fclose(f);
         return false;
     }

     char *buf = malloc((size_t)size + 1);
     if (!buf) {
         fclose(f);
         return false;
     }
     size_t rd = fread(buf, 1, (size_t)size, f);
     buf[rd] = '\0';
     fclose(f);

     cJSON *root = cJSON_Parse(buf);
     if (!root) {
         /* cJSON_GetErrorPtr() points into `buf` - must read it before
          * freeing, or this prints garbage from freed heap memory. */
         const char *err = cJSON_GetErrorPtr();
         fprintf(stderr, RED "  [!] Failed to parse config JSON near: %.40s\n" RESET, err ? err : "unknown error");
         free(buf);
         return false;
     }
     free(buf);

     cJSON *dmi = cJSON_GetObjectItemCaseSensitive(root, "dmi");
     json_get_string(dmi, "sys_vendor", p->dmi_sys_vendor, sizeof(p->dmi_sys_vendor));
     json_get_string(dmi, "product_name", p->dmi_product_name, sizeof(p->dmi_product_name));
     json_get_string(dmi, "bios_vendor", p->dmi_bios_vendor, sizeof(p->dmi_bios_vendor));
     json_get_string(dmi, "board_vendor", p->dmi_board_vendor, sizeof(p->dmi_board_vendor));
     json_get_string(dmi, "chassis_vendor", p->dmi_chassis_vendor, sizeof(p->dmi_chassis_vendor));
     json_get_string(dmi, "bios_version", p->dmi_bios_version, sizeof(p->dmi_bios_version));
     json_get_string(dmi, "bios_date", p->dmi_bios_date, sizeof(p->dmi_bios_date));
     json_get_string(dmi, "board_name", p->dmi_board_name, sizeof(p->dmi_board_name));
     json_get_string(dmi, "product_family", p->dmi_product_family, sizeof(p->dmi_product_family));
     json_get_string(dmi, "chassis_type", p->dmi_chassis_type, sizeof(p->dmi_chassis_type));
     json_get_string(dmi, "product_version", p->dmi_product_version, sizeof(p->dmi_product_version));
     json_get_string(dmi, "board_version", p->dmi_board_version, sizeof(p->dmi_board_version));

     cJSON *dt = cJSON_GetObjectItemCaseSensitive(root, "devicetree");
     json_get_string(dt, "model", p->devicetree_model, sizeof(p->devicetree_model));
     json_get_string(dt, "compatible", p->devicetree_compatible, sizeof(p->devicetree_compatible));

     json_get_string(root, "mac", p->mac, sizeof(p->mac));

     cJSON *cpu = cJSON_GetObjectItemCaseSensitive(root, "cpu");
     if (cpu) {
         cJSON *cores = cJSON_GetObjectItemCaseSensitive(cpu, "cores");
         if (cores && cJSON_IsNumber(cores)) {
             int c = (int)cores->valuedouble;
             if (c >= 1 && c <= 9)
                 p->cpu_cores = (char)('0' + c);
             else
                 fprintf(stderr, YELLOW "  [!] cpu.cores must be 1-9, ignoring config value %d\n" RESET, c);
         }
         json_get_string(cpu, "microcode", p->cpu_microcode, sizeof(p->cpu_microcode));
         bool keep;
         if (json_get_bool(cpu, "keep_hypervisor_flag", &keep))
             p->cpu_keep_hypervisor_flag = keep;
     }

     cJSON *mem = cJSON_GetObjectItemCaseSensitive(root, "memory");
     if (mem) {
         unsigned int kb;
         if (json_get_uint(mem, "total_kb", &kb))
             p->mem_total_kb = kb;
     }

     cJSON *disk = cJSON_GetObjectItemCaseSensitive(root, "disk");
     json_get_string(disk, "model", p->disk_model, sizeof(p->disk_model));

     cJSON *pci = cJSON_GetObjectItemCaseSensitive(root, "pci");
     if (pci && cJSON_IsArray(pci)) {
         int n = cJSON_GetArraySize(pci);
         if (n > MAX_PCI_MAPPINGS) n = MAX_PCI_MAPPINGS;
         if (n > 0) {
             p->num_pci_mappings = 0;
             for (int i = 0; i < n; i++) {
                 cJSON *m = cJSON_GetArrayItem(pci, i);
                 cJSON *from = cJSON_GetObjectItemCaseSensitive(m, "from");
                 cJSON *to = cJSON_GetObjectItemCaseSensitive(m, "to");
                 if (from && cJSON_IsString(from) && to && cJSON_IsString(to)) {
                     strncpy(p->pci_mappings[p->num_pci_mappings].from, from->valuestring, 6);
                     strncpy(p->pci_mappings[p->num_pci_mappings].to, to->valuestring, 6);
                     p->num_pci_mappings++;
                 }
             }
         }
     }

     cJSON *modules = cJSON_GetObjectItemCaseSensitive(root, "modules_to_hide");
     if (modules && cJSON_IsArray(modules)) {
         int n = cJSON_GetArraySize(modules);
         if (n > MAX_MODULES_TO_HIDE) n = MAX_MODULES_TO_HIDE;
         if (n > 0) {
             p->num_modules_to_hide = 0;
             for (int i = 0; i < n; i++) {
                 cJSON *m = cJSON_GetArrayItem(modules, i);
                 if (m && cJSON_IsString(m) && m->valuestring) {
                     strncpy(p->modules_to_hide[p->num_modules_to_hide], m->valuestring,
                             sizeof(p->modules_to_hide[0]) - 1);
                     p->num_modules_to_hide++;
                 }
             }
         }
     }

     cJSON *hfiles = cJSON_GetObjectItemCaseSensitive(root, "hidden_files");
     if (hfiles && cJSON_IsArray(hfiles)) {
         int n = cJSON_GetArraySize(hfiles);
         if (n > MAX_HIDDEN_FILES) n = MAX_HIDDEN_FILES;
         if (n > 0) {
             p->num_hidden_files = 0;
             for (int i = 0; i < n; i++) {
                 cJSON *m = cJSON_GetArrayItem(hfiles, i);
                 if (m && cJSON_IsString(m) && m->valuestring) {
                     strncpy(p->hidden_files[p->num_hidden_files], m->valuestring,
                             sizeof(p->hidden_files[0]) - 1);
                     p->num_hidden_files++;
                 }
             }
         }
     }

     cJSON *hpaths = cJSON_GetObjectItemCaseSensitive(root, "hidden_paths");
     if (hpaths && cJSON_IsArray(hpaths)) {
         int n = cJSON_GetArraySize(hpaths);
         if (n > MAX_HIDDEN_PATHS) n = MAX_HIDDEN_PATHS;
         if (n > 0) {
             p->num_hidden_paths = 0;
             for (int i = 0; i < n; i++) {
                 cJSON *m = cJSON_GetArrayItem(hpaths, i);
                 if (m && cJSON_IsString(m) && m->valuestring) {
                     strncpy(p->hidden_paths[p->num_hidden_paths], m->valuestring,
                             sizeof(p->hidden_paths[0]) - 1);
                     p->num_hidden_paths++;
                 }
             }
         }
     }

     json_get_uint(root, "uptime_seconds", &p->uptime_seconds);
     json_get_uint(root, "fake_cpu_count", &p->fake_cpu_count);

     cJSON_Delete(root);
     return true;
 }

 /* Scans argv for -c/--config <path>; loads it over the built-in defaults
  * if present. Silently keeps defaults if no flag is given (zero-config
  * behavior is unchanged from before this feature existed). Returns false
  * if -c/--config was given but the file failed to load/parse, so callers
  * can abort instead of silently spoofing with the wrong (default)
  * profile. */
 static bool load_profile(int argc, char **argv, struct nogitsune_profile *p)
 {
     init_default_profile(p);
     for (int i = 0; i < argc; i++) {
         if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && i + 1 < argc) {
             if (!load_profile_from_json(argv[i + 1], p))
                 return false;
             printf(BCYAN "  [*] Loaded config: %s\n" RESET, argv[i + 1]);
             break;
         }
     }
     return true;
 }

 /* Serializes a profile to the same JSON schema load_profile_from_json()
  * reads, so "init-config" always reflects the real current defaults -
  * there's no separate hardcoded template to drift out of sync. Caller
  * owns the returned object (cJSON_Delete it). */
 static cJSON *profile_to_json(const struct nogitsune_profile *p)
 {
     cJSON *root = cJSON_CreateObject();

     cJSON *dmi = cJSON_CreateObject();
     cJSON_AddStringToObject(dmi, "sys_vendor", p->dmi_sys_vendor);
     cJSON_AddStringToObject(dmi, "product_name", p->dmi_product_name);
     cJSON_AddStringToObject(dmi, "bios_vendor", p->dmi_bios_vendor);
     cJSON_AddStringToObject(dmi, "board_vendor", p->dmi_board_vendor);
     cJSON_AddStringToObject(dmi, "chassis_vendor", p->dmi_chassis_vendor);
     cJSON_AddStringToObject(dmi, "bios_version", p->dmi_bios_version);
     cJSON_AddStringToObject(dmi, "bios_date", p->dmi_bios_date);
     cJSON_AddStringToObject(dmi, "board_name", p->dmi_board_name);
     cJSON_AddStringToObject(dmi, "product_family", p->dmi_product_family);
     cJSON_AddStringToObject(dmi, "chassis_type", p->dmi_chassis_type);
     cJSON_AddStringToObject(dmi, "product_version", p->dmi_product_version);
     cJSON_AddStringToObject(dmi, "board_version", p->dmi_board_version);
     cJSON_AddItemToObject(root, "dmi", dmi);

     cJSON *dt = cJSON_CreateObject();
     cJSON_AddStringToObject(dt, "model", p->devicetree_model);
     cJSON_AddStringToObject(dt, "compatible", p->devicetree_compatible);
     cJSON_AddItemToObject(root, "devicetree", dt);

     cJSON_AddStringToObject(root, "mac", p->mac);

     cJSON *cpu = cJSON_CreateObject();
     cJSON_AddNumberToObject(cpu, "cores", p->cpu_cores - '0');
     cJSON_AddStringToObject(cpu, "microcode", p->cpu_microcode);
     cJSON_AddBoolToObject(cpu, "keep_hypervisor_flag", p->cpu_keep_hypervisor_flag);
     cJSON_AddItemToObject(root, "cpu", cpu);

     cJSON *mem = cJSON_CreateObject();
     cJSON_AddNumberToObject(mem, "total_kb", p->mem_total_kb);
     cJSON_AddItemToObject(root, "memory", mem);

     cJSON *disk = cJSON_CreateObject();
     cJSON_AddStringToObject(disk, "model", p->disk_model);
     cJSON_AddItemToObject(root, "disk", disk);

     cJSON *pci = cJSON_CreateArray();
     for (int i = 0; i < p->num_pci_mappings; i++) {
         cJSON *m = cJSON_CreateObject();
         cJSON_AddStringToObject(m, "from", p->pci_mappings[i].from);
         cJSON_AddStringToObject(m, "to", p->pci_mappings[i].to);
         cJSON_AddItemToArray(pci, m);
     }
     cJSON_AddItemToObject(root, "pci", pci);

     cJSON *modules = cJSON_CreateArray();
     for (int i = 0; i < p->num_modules_to_hide; i++) {
         cJSON_AddItemToArray(modules, cJSON_CreateString(p->modules_to_hide[i]));
     }
     cJSON_AddItemToObject(root, "modules_to_hide", modules);

     cJSON *hfiles = cJSON_CreateArray();
     for (int i = 0; i < p->num_hidden_files; i++) {
         cJSON_AddItemToArray(hfiles, cJSON_CreateString(p->hidden_files[i]));
     }
     cJSON_AddItemToObject(root, "hidden_files", hfiles);

     cJSON *hpaths = cJSON_CreateArray();
     for (int i = 0; i < p->num_hidden_paths; i++) {
         cJSON_AddItemToArray(hpaths, cJSON_CreateString(p->hidden_paths[i]));
     }
     cJSON_AddItemToObject(root, "hidden_paths", hpaths);

     cJSON_AddNumberToObject(root, "uptime_seconds", p->uptime_seconds);
     cJSON_AddNumberToObject(root, "fake_cpu_count", p->fake_cpu_count);

     return root;
 }

 /* ========================================================================== */
 /* SPOOFER LAUNCHING                                                          */
 /* ========================================================================== */

static void resolve_path(const char *bin, char *out, size_t out_size)
{
    if (bin[0] == '.' && bin[1] == '/') {
        snprintf(out, out_size, "%s/%s", g_exe_dir, bin + 2);
    } else {
        strncpy(out, bin, out_size - 1);
        out[out_size - 1] = '\0';
    }
}

static int launch_spoofer(spoofer_t *spoofer, const struct nogitsune_profile *profile,
                           const char *disk, const char *iface)
 {
     pid_t pid = fork();

    if (pid == 0) {
        /* Child process */
        freopen("/dev/null", "w", stdout);
        freopen("/dev/null", "w", stderr);

        char full_path[512];
        resolve_path(spoofer->binary, full_path, sizeof(full_path));

        char *args[48];
        int n = 0;
        args[n++] = (char *)spoofer->binary;

        char cores_str[2];
        char mem_kb_str[16];
        char pci_map_bufs[MAX_PCI_MAPPINGS][16];
        char uptime_str[16];
        char cpucount_str[16];
        char target_path[256];
        char real_value[64];
        char configured_padded[64];

        switch (spoofer->type) {
        case SPOOF_TYPE_BPF:
            if (strcmp(spoofer->name, "hwid") == 0) {
                if (strcmp(spoofer->binary, "./devicetree_spoof") == 0) {
                    args[n++] = "--model"; args[n++] = (char *)profile->devicetree_model;
                    args[n++] = "--compatible"; args[n++] = (char *)profile->devicetree_compatible;
                } else {
                    args[n++] = "--sys-vendor"; args[n++] = (char *)profile->dmi_sys_vendor;
                    args[n++] = "--product-name"; args[n++] = (char *)profile->dmi_product_name;
                    args[n++] = "--bios-vendor"; args[n++] = (char *)profile->dmi_bios_vendor;
                    args[n++] = "--board-vendor"; args[n++] = (char *)profile->dmi_board_vendor;
                    args[n++] = "--chassis-vendor"; args[n++] = (char *)profile->dmi_chassis_vendor;
                    args[n++] = "--bios-version"; args[n++] = (char *)profile->dmi_bios_version;
                    args[n++] = "--bios-date"; args[n++] = (char *)profile->dmi_bios_date;
                    args[n++] = "--board-name"; args[n++] = (char *)profile->dmi_board_name;
                    args[n++] = "--product-family"; args[n++] = (char *)profile->dmi_product_family;
                    args[n++] = "--chassis-type"; args[n++] = (char *)profile->dmi_chassis_type;
                    args[n++] = "--product-version"; args[n++] = (char *)profile->dmi_product_version;
                    args[n++] = "--board-version"; args[n++] = (char *)profile->dmi_board_version;
                }
            } else if (strcmp(spoofer->name, "cpu") == 0) {
                cores_str[0] = profile->cpu_cores;
                cores_str[1] = '\0';
                args[n++] = "--cores"; args[n++] = cores_str;
                args[n++] = "--microcode"; args[n++] = (char *)profile->cpu_microcode;
                if (profile->cpu_keep_hypervisor_flag)
                    args[n++] = "--keep-hypervisor-flag";
            } else if (strcmp(spoofer->name, "mem") == 0) {
                snprintf(mem_kb_str, sizeof(mem_kb_str), "%u", profile->mem_total_kb);
                args[n++] = "--mem-total-kb"; args[n++] = mem_kb_str;
            } else if (strcmp(spoofer->name, "pci") == 0) {
                int max_maps = profile->num_pci_mappings;
                if (max_maps > MAX_PCI_MAPPINGS) max_maps = MAX_PCI_MAPPINGS;
                for (int i = 0; i < max_maps; i++) {
                    snprintf(pci_map_bufs[i], sizeof(pci_map_bufs[i]), "%s:%s",
                             profile->pci_mappings[i].from, profile->pci_mappings[i].to);
                    args[n++] = "--vendor-map"; args[n++] = pci_map_bufs[i];
                }
            } else if (strcmp(spoofer->name, "mac-ioctl") == 0 || strcmp(spoofer->name, "mac-netlink") == 0) {
                args[n++] = "--iface"; args[n++] = (char *)iface;
                args[n++] = "--mac"; args[n++] = (char *)profile->mac;
            } else if (strcmp(spoofer->name, "modules") == 0) {
                int max_mods = profile->num_modules_to_hide;
                if (max_mods > MAX_MODULES_TO_HIDE) max_mods = MAX_MODULES_TO_HIDE;
                for (int i = 0; i < max_mods; i++) {
                    args[n++] = "--module"; args[n++] = (char *)profile->modules_to_hide[i];
                }
            } else if (strcmp(spoofer->name, "artifacts-fshide") == 0) {
                int max_files = profile->num_hidden_files;
                if (max_files > MAX_HIDDEN_FILES) max_files = MAX_HIDDEN_FILES;
                for (int i = 0; i < max_files; i++) {
                    args[n++] = "--name"; args[n++] = (char *)profile->hidden_files[i];
                }
            } else if (strcmp(spoofer->name, "artifacts-pathdeny") == 0) {
                int max_paths = profile->num_hidden_paths;
                if (max_paths > MAX_HIDDEN_PATHS) max_paths = MAX_HIDDEN_PATHS;
                for (int i = 0; i < max_paths; i++) {
                    args[n++] = "--path"; args[n++] = (char *)profile->hidden_paths[i];
                }
            } else if (strcmp(spoofer->name, "uptime") == 0) {
                snprintf(uptime_str, sizeof(uptime_str), "%u", profile->uptime_seconds);
                args[n++] = "--uptime-seconds"; args[n++] = uptime_str;
            } else if (strcmp(spoofer->name, "cpucount") == 0) {
                snprintf(cpucount_str, sizeof(cpucount_str), "%u", profile->fake_cpu_count);
                args[n++] = "--fake-cpu-count"; args[n++] = cpucount_str;
            }
            /* "kmsg" takes no arguments - patterns are fixed, nothing to pass. */
            args[n] = NULL;
            execv(full_path, args);
            break;

        case SPOOF_TYPE_TEXTREPLACE:
            if (strcmp(spoofer->name, "mac-file") == 0) {
                snprintf(target_path, sizeof(target_path), "/sys/class/net/%s/address", iface);
                char *real = read_file_line(target_path);
                strncpy(real_value, real ? real : VBOX_MAC_OUI, sizeof(real_value) - 1);
                real_value[sizeof(real_value) - 1] = '\0';
                pad_or_truncate(configured_padded, sizeof(configured_padded), profile->mac, strlen(real_value));
            } else if (strcmp(spoofer->name, "disk-sysblock") == 0) {
                snprintf(target_path, sizeof(target_path), "/sys/block/%s/device/model", disk);
                char *real = read_file_line(target_path);
                strncpy(real_value, real ? real : "VBOX HARDDISK", sizeof(real_value) - 1);
                real_value[sizeof(real_value) - 1] = '\0';
                pad_or_truncate(configured_padded, sizeof(configured_padded), profile->disk_model, strlen(real_value));
            } else if (strcmp(spoofer->name, "disk-classblock") == 0) {
                snprintf(target_path, sizeof(target_path), "/sys/class/block/%s/device/model", disk);
                char *real = read_file_line(target_path);
                strncpy(real_value, real ? real : "VBOX HARDDISK", sizeof(real_value) - 1);
                real_value[sizeof(real_value) - 1] = '\0';
                pad_or_truncate(configured_padded, sizeof(configured_padded), profile->disk_model, strlen(real_value));
            }
            execl(full_path, spoofer->binary,
                  "-f", target_path,
                  "-i", real_value,
                  "-r", configured_padded,
                  NULL);
            break;
        }

         /* If we get here, exec failed */
         _exit(1);
     } else if (pid > 0) {
         spoofer->pid = pid;
         return 0;
     } else {
         return -1;
     }
 }

 /* ========================================================================== */
 /* STEALTH MODE                                                               */
 /* ========================================================================== */

static int launch_pidhide_stealth(void)
{
    char ph_path[512];
    resolve_path("./pidhide", ph_path, sizeof(ph_path));

    if (!file_exists(ph_path)) {
        printf("  " YELLOW "[!]" RESET " pidhide not found - stealth mode unavailable\n");
        return -1;
    }

    printf(BCYAN "  [*] Engaging stealth mode...\n" RESET);

    pid_t pid = fork();
    if (pid == 0) {
        /* Build command with all process names to hide */
        char cmd[2048];
        snprintf(cmd, sizeof(cmd), "%s", ph_path);

         /* Hide all running spoofers */
         for (int i = 0; spoofers[i].name != NULL; i++) {
             if (spoofers[i].pid > 0) {
                 const char *name = spoofers[i].binary;
                 if (strncmp(name, "./", 2) == 0) name += 2;

                 strcat(cmd, " -n ");
                 strcat(cmd, name);
             }
         }

         /* Also auto-hide known Guest-Additions noise processes (confirmed
          * via live testing to be running unhidden on a real VirtualBox
          * guest: VBoxService + several paired VBoxClient instances) - the
          * user doesn't have to know to enumerate these themselves every
          * time. pidhide re-resolves -n entries periodically, so this
          * survives them crashing/respawning with a new PID. */
         static const char *guest_addition_names[] = {
             "VBoxService", "VBoxClient", "VBoxControl", "VBoxDRMClient",
         };
         for (size_t i = 0; i < sizeof(guest_addition_names) / sizeof(guest_addition_names[0]); i++) {
             strcat(cmd, " -n ");
             strcat(cmd, guest_addition_names[i]);
         }

         /* Also hide pidhide and nogitsune */
         strcat(cmd, " -n pidhide -n nogitsune -s");

         freopen("/dev/null", "w", stdout);
         freopen("/dev/null", "w", stderr);
         execl("/bin/sh", "sh", "-c", cmd, NULL);
         exit(1);
     } else if (pid > 0) {
         g_pidhide_pid = pid;
         usleep(150000);  /* 150ms for pidhide to load */
         printf("  " BGREEN "[✓]" RESET " Stealth active - processes hidden from /proc\n");
         return 0;
     }
     return -1;
 }

 /* ========================================================================== */
 /* PER-SUBCOMMAND HELP                                                       */
 /* ========================================================================== */

 static void print_spoof_help(void)
 {
     printf(BOLD "nogitsune spoof" RESET " - load spoofers and make this VM look like real hardware\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    sudo %s spoof [target flags] [-c PATH] [--stealth] [--background]\n\n", PROGNAME);
     printf(BOLD "TARGET FLAGS (default: all)\n" RESET);
     printf("    --dmi              Hardware identity only (DMI, or Device Tree on ARM64 without DMI)\n");
     printf("    --mac              MAC address only (ioctl + netlink + sysfs file, all 3 methods)\n");
     printf("    --cpu              /proc/cpuinfo only - automatically skipped on ARM64 (no x86 hypervisor field)\n");
     printf("    --mem              /proc/meminfo only\n");
     printf("    --pci              PCI vendor/device IDs only\n");
     printf("    --disk             Disk model only\n");
     printf("    --modules          Also hide kernel modules (off by default even with --all)\n");
     printf("    --artifacts        Guest Additions artifact hiding only (fshide + pathdeny)\n");
     printf("    --uptime           /proc/uptime only\n");
     printf("    --cpucount         sched_getaffinity CPU count only\n");
     printf("    --kmsg             Live kernel-log sanitization only\n\n");
     printf(BOLD "PROFILE & RUN MODE\n" RESET);
     printf("    -c, --config PATH  Load a custom JSON profile (see 'nogitsune init-config --help')\n");
     printf("    --stealth          Also hide spoofer processes from ps/top via pidhide\n");
     printf("    -d, --background   Detach and keep running after this shell exits (logs to %s)\n\n", NOGITSUNE_LOGFILE);
     printf(BOLD "EXAMPLES:\n" RESET);
     printf("    sudo %s spoof --stealth\n", PROGNAME);
     printf("    sudo %s spoof -c my-profile.json --background\n", PROGNAME);
     printf("    sudo %s spoof --dmi --mac\n\n", PROGNAME);
     printf(DIM "Only one spoof session can run at a time - 'spoof' refuses to start a second\n" RESET);
     printf(DIM "one while '%s status' shows a session already active. Use '%s stop' first.\n" RESET, PROGNAME, PROGNAME);
 }

 static void print_check_help(void)
 {
     printf(BOLD "nogitsune check" RESET " - dry run, preview what 'spoof' would change (no root needed)\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    %s check [-c PATH]\n\n", PROGNAME);
     printf("    -c, --config PATH  Preview a custom JSON profile instead of the built-in defaults\n\n");
     printf(BOLD "EXAMPLES:\n" RESET);
     printf("    %s check\n", PROGNAME);
     printf("    %s check -c my-profile.json\n", PROGNAME);
 }

 static void print_status_help(void)
 {
     printf(BOLD "nogitsune status" RESET " - scan this system for VM indicators, and show session state\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    sudo %s status\n\n", PROGNAME);
     printf("Reads real DMI/Device-Tree/network/CPU/memory/disk values (not a custom profile -\n");
     printf("use 'check -c PATH' to preview a profile instead) and reports whether a spoof\n");
     printf("session is currently active.\n");
 }

 static void print_stop_help(void)
 {
     printf(BOLD "nogitsune stop" RESET " - stop the running spoof session (foreground or --background)\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    sudo %s stop\n\n", PROGNAME);
     printf("Looks up the running session via %s and sends it SIGTERM (SIGKILL if it\n", NOGITSUNE_PIDFILE);
     printf("doesn't exit promptly), which cascades to stop every spoofer it launched,\n");
     printf("including pidhide if --stealth was used.\n");
 }

 static void print_hide_help(void)
 {
     printf(BOLD "nogitsune hide" RESET " - hide specific processes from /proc (independent of 'spoof')\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    sudo %s hide --pid <pids> | --name <names> [--self]\n\n", PROGNAME);
     printf("    -p, --pid <pids>   Hide by PID (comma-separated)\n");
     printf("    -n, --name <names> Hide by process name (comma-separated, resolved to PIDs)\n");
     printf("    -s, --self         Also hide this hide process itself\n\n");
     printf(BOLD "EXAMPLES:\n" RESET);
     printf("    sudo %s hide --name wireshark,tcpdump,gdb,strace\n", PROGNAME);
     printf("    sudo %s hide --pid 1234,5678 --self\n", PROGNAME);
 }

 static void print_initconfig_help(void)
 {
     printf(BOLD "nogitsune init-config" RESET " - write a starter JSON profile you can edit (no root needed)\n\n");
     printf(BOLD "USAGE:\n" RESET);
     printf("    %s init-config [path]\n\n", PROGNAME);
     printf("Writes the built-in default profile as JSON to [path] (default:\n");
     printf("./nogitsune-profile.json). Refuses to overwrite an existing file. Edit any\n");
     printf("field, then preview with 'check -c' before applying with 'spoof -c'.\n");
     printf("Full field reference: docs/CONFIGURATION.md\n\n");
     printf(BOLD "EXAMPLES:\n" RESET);
     printf("    %s init-config\n", PROGNAME);
     printf("    %s init-config /tmp/lenovo-profile.json\n", PROGNAME);
     printf("    sudo %s spoof -c /tmp/lenovo-profile.json\n", PROGNAME);
 }

 /* ========================================================================== */
 /* COMMANDS                                                                   */
 /* ========================================================================== */

 static int cmd_check(int argc, char **argv)
 {
     struct nogitsune_profile profile;
     if (!load_profile(argc, argv, &profile))
         return 1;

     hw_identity_t hw = detect_hw_identity();
     char disk[64] = "sda";
     char iface[64] = "eth0";
     bool have_disk = detect_primary_disk(disk, sizeof(disk));
     detect_primary_iface(iface, sizeof(iface));

     print_banner_small();
     printf(BYELLOW "  [*] DRY RUN - Showing what would be spoofed:\n\n" RESET);

     const char *arch = get_arch_string();
     bool is_arm = (strcmp(arch, "aarch64") == 0 || strcmp(arch, "arm64") == 0);
     printf("      " DIM "Architecture: %s%s\n" RESET, arch,
            is_arm ? "  (ARM64: cpuinfo spoof skipped, hwid = DMI or Device Tree)"
                   : "  (x86: DMI + cpuinfo spoof both run normally)");
     pid_t session_pid = read_pidfile();
     if (pid_is_running(session_pid)) {
         printf("      " YELLOW "[!] A spoof session is already running (PID %d) - this preview\n" RESET, session_pid);
         printf("      " YELLOW "    does not affect it; run '%s stop' first to apply a new one\n" RESET, PROGNAME);
     }
     printf("\n");

     printf("      " BOLD "%-18s %s\n" RESET, "Target", "Transformation");
     printf("      " DIM "%-18s %s\n" RESET, "──────────────────", "────────────────────────────────────────");

     if (hw == HW_IDENTITY_DEVICETREE) {
         printf("      %-18s %s\n", "model", profile.devicetree_model);
         printf("      %-18s %s\n", "compatible", profile.devicetree_compatible);
         printf("      " DIM "(no /sys/class/dmi/id on this host - using Device Tree)\n" RESET);
     } else {
         printf("      %-18s %s\n", "sys_vendor", profile.dmi_sys_vendor);
         printf("      %-18s %s\n", "product_name", profile.dmi_product_name);
         printf("      %-18s %s\n", "bios_vendor", profile.dmi_bios_vendor);
         printf("      %-18s %s\n", "bios_version", profile.dmi_bios_version);
         printf("      %-18s %s\n", "board_vendor", profile.dmi_board_vendor);
         printf("      %-18s %s\n", "board_name", profile.dmi_board_name);
         printf("      %-18s %s\n", "chassis_vendor", profile.dmi_chassis_vendor);
         if (hw == HW_IDENTITY_NONE) {
             printf("      " DIM "(skipped - no DMI or Device Tree detected on this host)\n" RESET);
         }
     }

     printf("      %-18s %s\n", "MAC (all methods)", profile.mac);
     if (is_arm) {
         printf("      " DIM "(hypervisor flag / cpu cores skipped - no 'hypervisor' field in ARM64 /proc/cpuinfo)\n" RESET);
     } else {
         printf("      %-18s %s\n", "hypervisor flag", profile.cpu_keep_hypervisor_flag ? "kept" : "removed");
         printf("      %-18s %c\n", "cpu cores", profile.cpu_cores);
     }
     printf("      %-18s %u kB (%u GB)\n", "MemTotal", profile.mem_total_kb, profile.mem_total_kb / 1024 / 1024);
     printf("      %-18s %s%s\n", "disk model", profile.disk_model, have_disk ? "" : "  (no disk detected)");
     for (int i = 0; i < profile.num_pci_mappings; i++) {
         printf("      %-18s %s  ->  %s\n", i == 0 ? "PCI vendor" : "",
                profile.pci_mappings[i].from, profile.pci_mappings[i].to);
     }
     printf("      %-18s %u seconds (%u days)\n", "uptime", profile.uptime_seconds,
            profile.uptime_seconds / 86400);
     printf("      %-18s %u\n", "CPU affinity count", profile.fake_cpu_count);
     for (int i = 0; i < profile.num_hidden_files; i++) {
         printf("      %-18s %s\n", i == 0 ? "hidden (listing)" : "", profile.hidden_files[i]);
     }
     for (int i = 0; i < profile.num_hidden_paths; i++) {
         printf("      %-18s %s\n", i == 0 ? "hidden (direct)" : "", profile.hidden_paths[i]);
     }

     printf("\n");
     printf("      " DIM "Detected disk: %s   Detected interface: %s\n" RESET, disk, iface);
     printf("\n");
     printf("  " BGREEN "[✓]" RESET " Run '" CYAN "sudo %s spoof" RESET "' to apply\n", PROGNAME);
     printf("  " BCYAN "[i]" RESET " Add '" CYAN "--stealth" RESET "' to hide spoofer processes\n");
     printf("\n");
     return 0;
 }

 static int cmd_init_config(int argc, char **argv)
 {
     const char *path = "nogitsune-profile.json";
     for (int i = 0; i < argc; i++) {
         if (argv[i][0] != '-') {
             path = argv[i];
             break;
         }
     }

     if (file_exists(path)) {
         fprintf(stderr, RED "  [!] %s already exists - refusing to overwrite\n" RESET, path);
         fprintf(stderr, DIM "      Remove it first or pass a different path\n" RESET);
         return 1;
     }

     struct nogitsune_profile profile;
     init_default_profile(&profile);

     cJSON *json = profile_to_json(&profile);
     char *text = json ? cJSON_Print(json) : NULL;
     if (json) cJSON_Delete(json);
     if (!text) {
         fprintf(stderr, RED "  [!] Failed to generate profile JSON\n" RESET);
         return 1;
     }

     FILE *f = fopen(path, "w");
     if (!f) {
         fprintf(stderr, RED "  [!] Cannot create %s: %s\n" RESET, path, strerror(errno));
         free(text);
         return 1;
     }
     fputs(text, f);
     fputc('\n', f);
     fclose(f);
     free(text);

     printf(BGREEN "  [✓]" RESET " Wrote default profile to " CYAN "%s" RESET "\n\n", path);
     printf(DIM "      Edit any field, then:\n" RESET);
     printf("        %s check -c %s    " DIM "# preview\n" RESET, PROGNAME, path);
     printf("        sudo %s spoof -c %s\n", PROGNAME, path);
     printf("\n" DIM "      Full field reference: docs/CONFIGURATION.md\n" RESET);
     return 0;
 }

 static int cmd_status(int argc, char **argv)
 {
     (void)argc; (void)argv;

     print_banner_small();
     printf(BYELLOW "  [*] Scanning for VM indicators...\n\n" RESET);

     const char *arch = get_arch_string();
     pid_t session_pid = read_pidfile();
     if (pid_is_running(session_pid)) {
         printf("  " BOLD "Session:" RESET " " BGREEN "active" RESET " (PID %d)   " BOLD "Arch:" RESET " %s\n\n",
                session_pid, arch);
     } else {
         printf("  " BOLD "Session:" RESET " " DIM "not running" RESET "   " BOLD "Arch:" RESET " %s\n\n", arch);
     }

     int vm_indicators = 0;
     int total_checks = 0;

     hw_identity_t hw = detect_hw_identity();

     if (hw == HW_IDENTITY_DMI) {
         printf(BOLD "  DMI/SMBIOS:\n" RESET);
         const char *dmi_files[] = {
             "/sys/class/dmi/id/sys_vendor",
             "/sys/class/dmi/id/product_name",
             "/sys/class/dmi/id/bios_vendor",
             "/sys/class/dmi/id/board_vendor",
             "/sys/class/dmi/id/board_name",
             "/sys/class/dmi/id/chassis_vendor",
             NULL
         };

         for (int i = 0; dmi_files[i] != NULL; i++) {
             char *val = read_file_line(dmi_files[i]);
             const char *name = strrchr(dmi_files[i], '/') + 1;
             total_checks++;
             if (val) {
                 if (is_vbox_string(val)) {
                     printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VM detected" RESET "\n", name, val);
                     vm_indicators++;
                 } else {
                     printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", name, val);
                 }
             }
         }
     } else if (hw == HW_IDENTITY_DEVICETREE) {
         printf(BOLD "  Device Tree:\n" RESET);
         const char *dt_files[] = {
             "/proc/device-tree/model",
             "/proc/device-tree/compatible",
             NULL
         };
         for (int i = 0; dt_files[i] != NULL; i++) {
             char *val = read_file_line(dt_files[i]);
             const char *name = strrchr(dt_files[i], '/') + 1;
             total_checks++;
             if (val) {
                 if (is_vbox_string(val)) {
                     printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VM detected" RESET "\n", name, val);
                     vm_indicators++;
                 } else {
                     printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", name, val);
                 }
             }
         }
     } else {
         printf(BOLD "  Hardware identity:\n" RESET);
         printf("      " DIM "[i] No /sys/class/dmi/id or /proc/device-tree found on this host" RESET "\n");
     }

     /* MAC address */
     printf("\n" BOLD "  Network:\n" RESET);
     char iface[64];
     if (detect_primary_iface(iface, sizeof(iface))) {
         char path[300];
         snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);
         char *mac = read_file_line(path);
         if (mac) {
             total_checks++;
             if (strncmp(mac, "08:00:27", 8) == 0) {
                 printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VirtualBox OUI" RESET "\n", iface, mac);
                 vm_indicators++;
             } else {
                 printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", iface, mac);
             }
         }
     } else {
         printf("      " DIM "[i] No network interface detected" RESET "\n");
     }

     /* CPU info */
     printf("\n" BOLD "  CPU:\n" RESET);
     FILE *f = fopen("/proc/cpuinfo", "r");
     if (f) {
         char line[512];
         bool found_hypervisor = false;
         int cores = 0;

         while (fgets(line, sizeof(line), f)) {
             if (strstr(line, "hypervisor")) found_hypervisor = true;
             if (strncmp(line, "processor", 9) == 0) cores++;
         }
         fclose(f);

         total_checks++;
         if (found_hypervisor) {
             printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VM detected" RESET "\n", "hypervisor", "present");
             vm_indicators++;
         } else {
             printf("      " GREEN "[✓]" RESET " %-16s " GREEN "not present" RESET "\n", "hypervisor");
         }
         printf("      " DIM "[i]" RESET " %-16s %d\n", "cores", cores);
     }

     /* Memory */
     printf("\n" BOLD "  Memory:\n" RESET);
     f = fopen("/proc/meminfo", "r");
     if (f) {
         char line[256];
         if (fgets(line, sizeof(line), f)) {
             unsigned long kb = 0;
             sscanf(line, "MemTotal: %lu", &kb);
             unsigned long gb = kb / 1024 / 1024;

             total_checks++;
             if (gb < 4) {
                 printf("      " YELLOW "[!]" RESET " %-16s " YELLOW "%lu GB" RESET " " DIM "← suspiciously low" RESET "\n", "MemTotal", gb);
             } else {
                 printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%lu GB" RESET "\n", "MemTotal", gb);
             }
         }
         fclose(f);
     }

     /* Disk */
     printf("\n" BOLD "  Storage:\n" RESET);
     char disk[64];
     if (detect_primary_disk(disk, sizeof(disk))) {
         char path[300];
         snprintf(path, sizeof(path), "/sys/class/block/%s/device/model", disk);
         char *disk_model = read_file_line(path);
         if (disk_model) {
             total_checks++;
             if (is_vbox_string(disk_model)) {
                 printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VM detected" RESET "\n", "disk model", disk_model);
                 vm_indicators++;
             } else {
                 printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", "disk model", disk_model);
             }
         }
     } else {
         printf("      " DIM "[i] No disk detected" RESET "\n");
     }

     /* Guest Additions artifacts - direct existence checks for the same
      * fixed, version-independent paths pathdeny defaults to hiding
      * (the version-suffixed /opt/VBoxGuestAdditions-X.Y.Z directory
      * fshide handles isn't checked here, since scanning for it requires
      * a directory walk rather than a simple existence check). */
     printf("\n" BOLD "  Artifacts:\n" RESET);
     static const char *artifact_paths[] = {
         "/usr/sbin/VBoxService", "/usr/bin/VBoxClient",
         "/usr/bin/VBoxControl", "/usr/sbin/mount.vboxsf",
     };
     bool any_artifact_found = false;
     for (size_t i = 0; i < sizeof(artifact_paths) / sizeof(artifact_paths[0]); i++) {
         if (file_exists(artifact_paths[i])) {
             total_checks++;
             printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← Guest Additions present" RESET "\n",
                    "artifact", artifact_paths[i]);
             vm_indicators++;
             any_artifact_found = true;
         }
     }
     if (!any_artifact_found) {
         total_checks++;
         printf("      " GREEN "[✓]" RESET " %-16s " GREEN "none found" RESET "\n", "artifacts");
     }

     /* Summary */
     printf("\n");
     printf("  ════════════════════════════════════════════════════════════════\n");
     if (vm_indicators > 0) {
         printf("  " BRED "  ⚠  DETECTED: %d VM indicator(s)" RESET "\n", vm_indicators);
         printf("  " DIM "     Malware will likely detect this environment" RESET "\n");
         printf("\n");
         printf("  " BYELLOW "  →" RESET " Run '" CYAN "sudo %s spoof --stealth" RESET "' to fix\n", PROGNAME);
     } else {
         printf("  " BGREEN "  ✓  CLEAN: No obvious VM indicators" RESET "\n");
         printf("  " DIM "     Note: CPUID/RDTSC checks require hypervisor-level fixes" RESET "\n");
     }
     printf("\n");

     return 0;
 }

 static int cmd_spoof(int argc, char **argv)
 {
     /* Refuse to start a second concurrent session - this is also what
      * makes 'stop' reliable: there's only ever at most one PID to track. */
     pid_t existing = read_pidfile();
     if (pid_is_running(existing)) {
         fprintf(stderr, RED "  [!] nogitsune is already running (PID %d)\n" RESET, existing);
         fprintf(stderr, DIM "      Run 'sudo %s stop' first, or check 'sudo %s status'\n" RESET,
                 PROGNAME, PROGNAME);
         return 1;
     }

     bool specific_spoofers = false;
     bool stealth = false;
     bool enable_modules = false;
     bool background = false;

     struct nogitsune_profile profile;
     if (!load_profile(argc, argv, &profile))
         return 1;

     /* Parse options */
     for (int i = 0; i < argc; i++) {
         if (strcmp(argv[i], "--stealth") == 0 || strcmp(argv[i], "-s") == 0) {
             stealth = true;
         } else if (strcmp(argv[i], "--background") == 0 || strcmp(argv[i], "-d") == 0 ||
                    strcmp(argv[i], "--daemon") == 0) {
             background = true;
         } else if (strcmp(argv[i], "--modules") == 0) {
             enable_modules = true;
         } else if (strcmp(argv[i], "--dmi") == 0 ||
                    strcmp(argv[i], "--mac") == 0 ||
                    strcmp(argv[i], "--cpu") == 0 ||
                    strcmp(argv[i], "--mem") == 0 ||
                    strcmp(argv[i], "--pci") == 0 ||
                    strcmp(argv[i], "--disk") == 0 ||
                    strcmp(argv[i], "--artifacts") == 0 ||
                    strcmp(argv[i], "--uptime") == 0 ||
                    strcmp(argv[i], "--cpucount") == 0 ||
                    strcmp(argv[i], "--kmsg") == 0) {
             specific_spoofers = true;
         }
     }

     /* If specific spoofers requested, disable all first */
     if (specific_spoofers) {
         for (int i = 0; spoofers[i].name != NULL; i++) {
             spoofers[i].enabled = false;
         }

         /* Enable requested ones */
         for (int i = 0; i < argc; i++) {
             if (strcmp(argv[i], "--dmi") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "hwid") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--mac") == 0) {
                 /* Enable all 3 MAC methods */
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strncmp(spoofers[j].name, "mac", 3) == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--cpu") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "cpu") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--mem") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "mem") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--pci") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "pci") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--disk") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strncmp(spoofers[j].name, "disk", 4) == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--artifacts") == 0) {
                 /* fshide (directory-listing) + pathdeny (direct-path) are
                  * complementary facets of the same "hide Guest Additions
                  * footprint" concern - grouped as one unit. */
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strncmp(spoofers[j].name, "artifacts-", 10) == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--uptime") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "uptime") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--cpucount") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "cpucount") == 0)
                         spoofers[j].enabled = true;
             }
             else if (strcmp(argv[i], "--kmsg") == 0) {
                 for (int j = 0; spoofers[j].name != NULL; j++)
                     if (strcmp(spoofers[j].name, "kmsg") == 0)
                         spoofers[j].enabled = true;
             }
         }
     }

     /* Enable modules if requested */
     if (enable_modules) {
         for (int j = 0; spoofers[j].name != NULL; j++)
             if (strcmp(spoofers[j].name, "modules") == 0)
                 spoofers[j].enabled = true;
     }

     if (background) {
         pid_t child = daemonize_into_background();
         if (child < 0) {
             fprintf(stderr, RED "  [!] Failed to background: %s\n" RESET, strerror(errno));
             return 1;
         }
         if (child > 0) {
             /* Parent: report and return immediately, shell gets control back */
             printf(BGREEN "  [✓]" RESET " Started in background (PID %d)\n", child);
             printf(DIM "      Logs: %s\n" RESET, NOGITSUNE_LOGFILE);
             printf(DIM "      Stop: sudo %s stop\n" RESET, PROGNAME);
             return 0;
         }
         /* child == 0: this process is now the detached daemon - stdio is
          * redirected to NOGITSUNE_LOGFILE, everything below logs there */
     }

     print_banner();

     /* Resolve hardware identity (DMI vs Device Tree) */
     hw_identity_t hw = detect_hw_identity();
     for (int j = 0; spoofers[j].name != NULL; j++) {
         if (strcmp(spoofers[j].name, "hwid") != 0) continue;
         if (hw == HW_IDENTITY_DEVICETREE) {
             spoofers[j].binary = "./devicetree_spoof";
             spoofers[j].description = "Device Tree spoofing (model, compatible)";
             spoofers[j].target = "/proc/device-tree/*";
         } else if (hw == HW_IDENTITY_NONE) {
             spoofers[j].enabled = false;
             printf(YELLOW "  [!] No DMI or Device Tree found - hardware identity spoofing skipped\n" RESET);
         }
     }

#if defined(__aarch64__)
     /* ARM64 /proc/cpuinfo has no x86 'hypervisor' flag/CPUID-derived field
      * at all - cpuinfo_spoof's patterns are safe no-ops there, so skip
      * launching it rather than spoof a format that doesn't apply. */
     for (int j = 0; spoofers[j].name != NULL; j++) {
         if (strcmp(spoofers[j].name, "cpu") == 0) {
             spoofers[j].enabled = false;
         }
     }
#endif

     /* Auto-detect disk and network interface (heuristic - see README) */
     char disk[64] = "sda";
     char iface[64] = "eth0";
     if (!detect_primary_disk(disk, sizeof(disk))) {
         printf(YELLOW "  [!] No disk detected, falling back to 'sda'\n" RESET);
     }
     if (!detect_primary_iface(iface, sizeof(iface))) {
         printf(YELLOW "  [!] No network interface detected, falling back to 'eth0'\n" RESET);
     }

     printf(BYELLOW "  [*] Loading spoofers...\n" RESET);
     if (stealth) {
         printf(BCYAN "  [*] Stealth mode enabled\n" RESET);
     }
     printf("\n");

     int loaded = 0;
     int failed = 0;

     /* Launch each enabled spoofer */
     for (int i = 0; spoofers[i].name != NULL; i++) {
         if (!spoofers[i].enabled)
             continue;

        /* Check if binary exists */
        char check_path[512];
        resolve_path(spoofers[i].binary, check_path, sizeof(check_path));
        if (!file_exists(check_path)) {
             printf("      " RED "[✗]" RESET " %-16s " DIM "binary not found: %s" RESET "\n",
                    spoofers[i].name, spoofers[i].binary);
             failed++;
             continue;
         }

         /* Launch it */
         if (launch_spoofer(&spoofers[i], &profile, disk, iface) == 0) {
             printf("      " BGREEN "[✓]" RESET " %-16s %s\n",
                    spoofers[i].name, spoofers[i].description);
             loaded++;
             usleep(50000);  /* 50ms between launches */
         } else {
             printf("      " RED "[✗]" RESET " %-16s " DIM "launch failed: %s" RESET "\n",
                    spoofers[i].name, strerror(errno));
             failed++;
         }
     }

     printf("\n");

     /* Stealth mode */
     if (stealth && loaded > 0) {
         launch_pidhide_stealth();
         printf("\n");
     }

     /* Summary */
     printf("  ════════════════════════════════════════════════════════════════\n");
     if (loaded > 0) {
         printf("  " BGREEN "  ✓  ACTIVE:" RESET " %d spoofer(s) loaded", loaded);
         if (failed > 0) printf(YELLOW " (%d failed)" RESET, failed);
         printf("\n");
         printf("  " BCYAN "  ◉  Profile:" RESET " %s %s\n", profile.dmi_sys_vendor, profile.dmi_product_name);
         printf("  " BCYAN "  ◉  Disk:" RESET " %s   " BCYAN "Interface:" RESET " %s\n", disk, iface);
         if (stealth) {
             printf("  " BCYAN "  ◉  Stealth:" RESET " Processes hidden from /proc\n");
         }
         printf("\n");
         if (background) {
             printf("      " DIM "Running in background. Stop with: sudo %s stop" RESET "\n", PROGNAME);
         } else {
             printf("      " DIM "Press Ctrl+C to stop all spoofers (or run 'sudo %s stop' from another shell)" RESET "\n", PROGNAME);
         }
         printf("\n");
         fflush(stdout);

         write_pidfile(getpid());

         /* Wait for signal */
         pause();
     } else {
         printf("  " BRED "  ✗  No spoofers loaded" RESET "\n");
         printf("      " DIM "Run 'make' to build the tools first" RESET "\n");
         printf("\n");
         return 1;
     }

     return 0;
 }

static int cmd_stop(int argc, char **argv)
{
    (void)argc; (void)argv;

    print_banner_small();
    printf(BYELLOW "  [*] Stopping spoof session...\n\n" RESET);

    /* This runs as a separate process from whatever ran 'spoof', so it
     * can't rely on the spoofers[]/g_pidhide_pid in-memory state (that
     * only exists inside the original 'spoof' process) - it has to find
     * that process via the PID file and ask IT to clean up its own
     * children, the same way Ctrl+C in that process's own terminal would. */
    pid_t pid = read_pidfile();
    if (!pid_is_running(pid)) {
        printf("      " DIM "[*] No running spoof session found" RESET "\n");
        unlink(NOGITSUNE_PIDFILE); /* clean up a stale file, if any */
        printf("\n  " BGREEN "[✓] Cleanup complete" RESET "\n\n");
        return 0;
    }

    if (kill(pid, SIGTERM) != 0) {
        fprintf(stderr, RED "  [!] Failed to signal PID %d: %s\n" RESET, pid, strerror(errno));
        return 1;
    }
    printf("      " GREEN "[✓]" RESET " Sent stop signal to session (PID %d)\n", pid);

    /* Give its own sig_handler a moment to cascade-kill spoofers/pidhide
     * and remove the PID file, then force it if it's still around. */
    for (int i = 0; i < 10 && pid_is_running(pid); i++) {
        usleep(100000);
    }
    if (pid_is_running(pid)) {
        printf("      " YELLOW "[!]" RESET " Still running, forcing...\n");
        kill(pid, SIGKILL);
        unlink(NOGITSUNE_PIDFILE);
    }

    printf("\n  " BGREEN "[✓] Cleanup complete" RESET "\n\n");
    return 0;
}

 static int cmd_hide(int argc, char **argv)
 {
     char *pids = NULL;
     char *names = NULL;
     bool hide_self = false;

     for (int i = 0; i < argc; i++) {
         if ((strcmp(argv[i], "--pid") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
             pids = argv[++i];
         } else if ((strcmp(argv[i], "--name") == 0 || strcmp(argv[i], "-n") == 0) && i + 1 < argc) {
             names = argv[++i];
         } else if (strcmp(argv[i], "--self") == 0 || strcmp(argv[i], "-s") == 0) {
             hide_self = true;
         }
     }

     if (!pids && !names && !hide_self) {
         fprintf(stderr, RED "  [!] Specify --pid, --name, or --self\n" RESET);
         fprintf(stderr, DIM "      Example: %s hide --name wireshark,tcpdump\n" RESET, PROGNAME);
         return 1;
     }

     print_banner_small();

    if (!file_exists("./pidhide")) {
        fprintf(stderr, RED "  [!] pidhide not found - run 'make' first\n" RESET);
        return 1;
    }

    printf(BYELLOW "  [*] Starting process hiding...\n\n" RESET);

    /* Build command */
    char cmd[1024];
    char ph_path[512];
    resolve_path("./pidhide", ph_path, sizeof(ph_path));
    int pos = snprintf(cmd, sizeof(cmd), "%s", ph_path);

    if (pids) {
        char *copy = strdup(pids);
        char *tok = strtok(copy, ",");
        while (tok && pos < (int)sizeof(cmd) - 16) {
            pos += snprintf(cmd + pos, sizeof(cmd) - pos, " -p %s", tok);
            printf("      " CYAN "→" RESET " PID: %s\n", tok);
            tok = strtok(NULL, ",");
        }
        free(copy);
    }

    if (names) {
        char *copy = strdup(names);
        char *tok = strtok(copy, ",");
        while (tok && pos < (int)sizeof(cmd) - 16) {
            pos += snprintf(cmd + pos, sizeof(cmd) - pos, " -n %s", tok);
            printf("      " CYAN "→" RESET " Name: %s\n", tok);
            tok = strtok(NULL, ",");
        }
        free(copy);
    }

    if (hide_self && pos < (int)sizeof(cmd) - 4) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " -s");
        printf("      " CYAN "→" RESET " Self: yes\n");
    }

     printf("\n");

     pid_t pid = fork();
     if (pid == 0) {
         execl("/bin/sh", "sh", "-c", cmd, NULL);
         exit(1);
     } else if (pid > 0) {
         usleep(100000);
         printf("  " BGREEN "[✓]" RESET " Process hider active (PID: %d)\n", pid);
         printf("      " DIM "Press Ctrl+C to stop" RESET "\n\n");
         pause();
     }

     return 0;
 }

 /* ========================================================================== */
 /* SIGNAL HANDLER                                                             */
 /* ========================================================================== */

 static void sig_handler(int sig)
 {
     (void)sig;
     printf("\n\n" BYELLOW "  [*] Shutting down...\n" RESET);

     /* Kill all children */
     for (int i = 0; spoofers[i].name != NULL; i++) {
         if (spoofers[i].pid > 0) {
             kill(spoofers[i].pid, SIGTERM);
         }
     }

     if (g_pidhide_pid > 0) {
         kill(g_pidhide_pid, SIGTERM);
     }

     /* Only remove the PID file if it's actually tracking this process - a
      * Ctrl+C in 'check'/'status'/'hide' must never delete a different,
      * still-running spoof session's PID file. */
     if (read_pidfile() == getpid()) {
         unlink(NOGITSUNE_PIDFILE);
     }

     printf("  " BGREEN "[✓]" RESET " All spoofers stopped\n\n");
     exit(0);
 }

 /* ========================================================================== */
 /* MAIN                                                                       */
 /* ========================================================================== */

int main(int argc, char **argv)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Resolve real executable directory for relative path support */
    char exe_path[512];
    ssize_t rl_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (rl_len > 0) {
        exe_path[rl_len] = '\0';
        char *slash = strrchr(exe_path, '/');
        if (slash) *slash = '\0';
        strncpy(g_exe_dir, exe_path, sizeof(g_exe_dir) - 1);
    }

    if (argc < 2) {
         print_usage();
         return 1;
     }

     const char *cmd = argv[1];

     if (strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
         print_usage();
         return 0;
     }

     if (strcmp(cmd, "-v") == 0 || strcmp(cmd, "--version") == 0) {
         printf(BOLD "nogitsune" RESET " version " CYAN "%s" RESET "\n", VERSION);
         return 0;
     }

     int sub_argc = argc - 2;
     char **sub_argv = argv + 2;

     /* Commands not requiring root */
     if (strcmp(cmd, "check") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_check_help(); return 0; }
         return cmd_check(sub_argc, sub_argv);
     }
     if (strcmp(cmd, "init-config") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_initconfig_help(); return 0; }
         return cmd_init_config(sub_argc, sub_argv);
     }

     /* Commands requiring root - but "<command> --help" should work without
      * sudo, so check for that before the root gate. */
     if (strcmp(cmd, "spoof") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_spoof_help(); return 0; }
         if (!check_root()) return 1;
         return cmd_spoof(sub_argc, sub_argv);
     }
     if (strcmp(cmd, "status") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_status_help(); return 0; }
         if (!check_root()) return 1;
         return cmd_status(sub_argc, sub_argv);
     }
     if (strcmp(cmd, "stop") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_stop_help(); return 0; }
         if (!check_root()) return 1;
         return cmd_stop(sub_argc, sub_argv);
     }
     if (strcmp(cmd, "hide") == 0) {
         if (args_have_help(sub_argc, sub_argv)) { print_hide_help(); return 0; }
         if (!check_root()) return 1;
         return cmd_hide(sub_argc, sub_argv);
     }

     fprintf(stderr, RED "  [!] Unknown command: %s\n" RESET, cmd);
     fprintf(stderr, DIM "      Run '%s --help' for usage\n" RESET, PROGNAME);
     return 1;
 }
