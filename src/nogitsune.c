/*
 * Nogitsune - eBPF Anti-Sandbox Toolkit
 * Unified CLI for loading and managing spoofers
 * 
 * Usage:
 *   nogitsune spoof [--dmi] [--mac] [--cpu] [--mem] [--stealth]
 *   nogitsune check
 *   nogitsune status  
 *   nogitsune stop
 *   nogitsune hide --pid <pids> | --name <names>
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <unistd.h>
 #include <signal.h>
 #include <sys/wait.h>
 #include <sys/stat.h>
 #include <errno.h>
 #include <stdbool.h>
 #include <dirent.h>
 #include <time.h>
 
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
 
 /* Spoof profile - Dell OptiPlex 7090 */
 #define DELL_MAC_FULL    "a4:5e:60:12:34:56"
 #define DELL_MAC_OUI     "a4:5e:60"
 #define VBOX_MAC_OUI     "08:00:27"
 
 /* Spoofer types */
 typedef enum {
     SPOOF_TYPE_BPF,      /* eBPF binary */
     SPOOF_TYPE_SCRIPT,   /* Shell script */
     SPOOF_TYPE_TEXTREPLACE /* textreplace with args */
 } spoof_type_t;
 
 /* Spoofer definitions */
 typedef struct {
     const char *name;
     const char *binary;
     const char *args;         /* Arguments for the binary (NULL if none) */
     const char *description;
     const char *target;
     spoof_type_t type;
     bool enabled;
     pid_t pid;
 } spoofer_t;
 
 /* 
  * Global spoofer list
  * Order matters - some may depend on others
  */
 static spoofer_t spoofers[] = {
     /* DMI/SMBIOS - Core identity spoofing */
     {"dmi",         "./dmi_spoof",      NULL,
      "DMI/SMBIOS spoofing (10 files)",  "/sys/class/dmi/id/*",
      SPOOF_TYPE_BPF, true, 0},
 
     /* CPU - Remove hypervisor flag, increase cores */
     {"cpu",         "./cpuinfo_spoof",  NULL,
      "CPU info spoofing",               "/proc/cpuinfo",
      SPOOF_TYPE_BPF, true, 0},
 
     /* Memory - Increase RAM size */
     {"mem",         "./meminfo_spoof",  NULL,
      "Memory info spoofing (16GB)",     "/proc/meminfo",
      SPOOF_TYPE_BPF, true, 0},
 
     /* PCI - Change vendor IDs */
     {"pci",         "./pci_spoof",      NULL,
      "PCI device ID spoofing",          "/sys/bus/pci/devices/*/vendor",
      SPOOF_TYPE_BPF, true, 0},
 
     /* MAC Address - THREE methods for full coverage */
     {"mac-ioctl",   "./ioctl_spoof",    NULL,
      "MAC via ioctl (SIOCGIFHWADDR)",   "ioctl syscall",
      SPOOF_TYPE_BPF, true, 0},
 
     {"mac-netlink", "./netlink_spoof",  NULL,
      "MAC via netlink (RTM_GETLINK)",   "netlink socket",
      SPOOF_TYPE_BPF, true, 0},
 
     {"mac-file",    "./textreplace",    NULL,  /* args hardcoded in launch_spoofer() */
      "MAC via file read",               "/sys/class/net/*/address",
      SPOOF_TYPE_TEXTREPLACE, true, 0},
 
     /* Disk - Model and serial */
     {"disk",        "./disk_spoof.sh",  NULL,
      "Disk model/serial spoofing",      "/sys/class/block/*/device/*",
      SPOOF_TYPE_SCRIPT, true, 0},
 
     /* Kernel modules - Hide vbox modules (optional) */
     {"modules",     "./modules_hide",   NULL,
      "Kernel module hiding",            "/proc/modules",
      SPOOF_TYPE_BPF, false, 0},  /* Disabled by default */
 
     {NULL, NULL, NULL, NULL, NULL, SPOOF_TYPE_BPF, false, 0}
 };
 
 /* Spoofed values - for display */
 static const char *SPOOF_VALUES[][2] = {
     /* DMI/SMBIOS */
     {"sys_vendor",      "innotek GmbH       →  Dell Inc."},
     {"product_name",    "VirtualBox         →  OptiPlex 7090"},
     {"bios_vendor",     "innotek GmbH       →  Dell Inc."},
     {"bios_version",    "VirtualBox         →  2.1.3"},
     {"board_vendor",    "Oracle Corporation →  Dell Inc."},
     {"board_name",      "VirtualBox         →  0WN7Y6"},
     {"chassis_vendor",  "Oracle Corporation →  Dell Inc."},
     
     /* MAC - All three methods */
     {"MAC (ioctl)",     "08:00:27:xx:xx:xx  →  a4:5e:60:xx:xx:xx"},
     {"MAC (netlink)",   "08:00:27:xx:xx:xx  →  a4:5e:60:xx:xx:xx"},
     {"MAC (file)",      "08:00:27:xx:xx:xx  →  a4:5e:60:xx:xx:xx"},
     
     /* CPU */
     {"hypervisor flag", "present            →  removed"},
     {"cpu cores",       "2                  →  8"},
     
     /* Memory */
     {"MemTotal",        "2 GB               →  16 GB"},
     
     /* Disk */
     {"disk model",      "VBOX HARDDISK      →  Samsung SSD 970 EVO Plus"},
     {"disk serial",     "VB12345678         →  S4EVNF0M123456"},
     
     /* PCI */
     {"PCI vendor",      "0x80ee (VBox)      →  0x8086 (Intel)"},
     
     {NULL, NULL}
 };
 
 /* Global state */
 static bool g_stealth_mode = false;
 static pid_t g_pidhide_pid = 0;
 
 /* Forward declarations */
 static void print_banner(void);
 static void print_banner_small(void);
 static void print_usage(void);
 static int cmd_spoof(int argc, char **argv);
 static int cmd_check(int argc, char **argv);
 static int cmd_status(int argc, char **argv);
 static int cmd_stop(int argc, char **argv);
 static int cmd_hide(int argc, char **argv);
 static bool check_root(void);
 static bool file_exists(const char *path);
 static char *read_file_line(const char *path);
 static int launch_pidhide_stealth(void);
 static int launch_spoofer(spoofer_t *spoofer);
 
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
     printf(DIM "                        │" RESET BOLD "  野狐 " RESET CYAN "eBPF Anti-Sandbox Toolkit" DIM "  │\n" RESET);
     printf(DIM "                        │" RESET "     Make VMs Look Like Metal     " DIM "│\n" RESET);
     printf(DIM "                        ╰──────────────────────────────────╯\n" RESET);
     printf("\n");
 }
 
 static void print_banner_small(void)
 {
     printf("\n");
     printf(BYELLOW "  ┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓\n" RESET);
     printf(BYELLOW "  ┃" RESET BOLD " 野狐 " BRED "NOGITSUNE" RESET " ━ eBPF Anti-Sandbox Toolkit        " BYELLOW "┃\n" RESET);
     printf(BYELLOW "  ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛\n" RESET);
     printf("\n");
 }
 
 /* ========================================================================== */
 
 static void print_usage(void)
 {
     print_banner();
     
     printf(BOLD "USAGE:" RESET "\n");
     printf("    " CYAN "%s" RESET " <command> [options]\n\n", PROGNAME);
     
     printf(BOLD BYELLOW "COMMANDS:\n" RESET);
     printf("    " BGREEN "spoof" RESET "      Load all spoofers - make VM look like real hardware\n");
     printf("    " BGREEN "check" RESET "      Dry run - preview what would be changed\n");
     printf("    " BGREEN "status" RESET "     Scan system for VM indicators\n");
     printf("    " BGREEN "stop" RESET "       Kill all running spoofers\n");
     printf("    " BGREEN "hide" RESET "       Hide specific processes from /proc\n");
     printf("\n");
     
     printf(BOLD BYELLOW "SPOOF OPTIONS:\n" RESET);
     printf("    --all          Load all spoofers (default)\n");
     printf("    --dmi          DMI/SMBIOS only (sys_vendor, product_name, etc.)\n");
     printf("    --mac          MAC address only (all 3 methods: ioctl + netlink + file)\n");
     printf("    --cpu          CPU info only (hypervisor flag, cores)\n");
     printf("    --mem          Memory info only\n");
     printf("    --pci          PCI vendor IDs only\n");
     printf("    --disk         Disk model/serial only\n");
     printf("    --modules      Also hide kernel modules (vboxguest, etc.)\n");
     printf("    " BCYAN "--stealth" RESET "    " BRED "★" RESET " Hide spoofer processes from ps/top\n");
     printf("\n");
     
     printf(BOLD BYELLOW "HIDE OPTIONS:\n" RESET);
     printf("    -p, --pid <pids>   Hide by PID (comma-separated)\n");
     printf("    -n, --name <names> Hide by name (comma-separated)\n");
     printf("    -s, --self         Also hide this process\n");
     printf("\n");
     
     printf(BOLD BYELLOW "EXAMPLES:\n" RESET);
     printf(DIM "    # Full stealth mode - recommended for malware analysis\n" RESET);
     printf("    " WHITE "$ sudo %s spoof --stealth\n" RESET, PROGNAME);
     printf("\n");
     printf(DIM "    # Check for VM indicators before running malware\n" RESET);
     printf("    " WHITE "$ sudo %s status\n" RESET, PROGNAME);
     printf("\n");
     printf(DIM "    # Load specific spoofers only\n" RESET);
     printf("    " WHITE "$ sudo %s spoof --dmi --mac\n" RESET, PROGNAME);
     printf("\n");
     printf(DIM "    # Hide analysis tools from malware\n" RESET);
     printf("    " WHITE "$ sudo %s hide --name wireshark,tcpdump,gdb,strace\n" RESET, PROGNAME);
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
 /* SPOOFER LAUNCHING                                                          */
 /* ========================================================================== */
 
 static int launch_spoofer(spoofer_t *spoofer)
 {
     pid_t pid = fork();
     
     if (pid == 0) {
         /* Child process */
         freopen("/dev/null", "w", stdout);
         freopen("/dev/null", "w", stderr);
         
         switch (spoofer->type) {
             case SPOOF_TYPE_BPF:
                 /* Simple exec - direct, no shell */
                 execl(spoofer->binary, spoofer->binary, NULL);
                 break;
                 
             case SPOOF_TYPE_SCRIPT:
                 /* Shell script - need bash but use absolute path */
                 {
                     /* Get absolute path to avoid CWD issues */
                     char abs_path[512];
                     if (realpath(spoofer->binary, abs_path) != NULL) {
                         execl("/bin/bash", "bash", abs_path, NULL);
                     } else {
                         execl("/bin/bash", "bash", spoofer->binary, NULL);
                     }
                 }
                 break;
                 
             case SPOOF_TYPE_TEXTREPLACE:
                 /* 
                  * IMPORTANT: Don't use shell! Direct exec with args.
                  * Shell execution causes silent failures due to CWD issues.
                  * Args are: -f <file> -i <find> -r <replace>
                  */
                 execl(spoofer->binary, spoofer->binary,
                       "-f", "/sys/class/net/eth0/address",
                       "-i", VBOX_MAC_OUI,
                       "-r", DELL_MAC_OUI,
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
     if (!file_exists("./pidhide")) {
         printf("  " YELLOW "[!]" RESET " pidhide not found - stealth mode unavailable\n");
         return -1;
     }
     
     printf(BCYAN "  [*] Engaging stealth mode...\n" RESET);
     
     pid_t pid = fork();
     if (pid == 0) {
         /* Build command with all process names to hide */
         char cmd[2048] = "./pidhide";
         
         /* Hide all running spoofers */
         for (int i = 0; spoofers[i].name != NULL; i++) {
             if (spoofers[i].pid > 0) {
                 const char *name = spoofers[i].binary;
                 if (strncmp(name, "./", 2) == 0) name += 2;
                 
                 /* Skip shell scripts - hide by PID instead */
                 if (spoofers[i].type == SPOOF_TYPE_SCRIPT) {
                     char pid_arg[32];
                     snprintf(pid_arg, sizeof(pid_arg), " -p %d", spoofers[i].pid);
                     strcat(cmd, pid_arg);
                 } else {
                     strcat(cmd, " -n ");
                     strcat(cmd, name);
                 }
             }
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
 /* COMMANDS                                                                   */
 /* ========================================================================== */
 
 static int cmd_check(int argc, char **argv)
 {
     (void)argc; (void)argv;
     
     print_banner_small();
     printf(BYELLOW "  [*] DRY RUN - Showing what would be spoofed:\n\n" RESET);
     
     printf("      " BOLD "%-18s %s\n" RESET, "Target", "Transformation");
     printf("      " DIM "%-18s %s\n" RESET, "──────────────────", "────────────────────────────────────────");
     
     for (int i = 0; SPOOF_VALUES[i][0] != NULL; i++) {
         printf("      %-18s %s\n", SPOOF_VALUES[i][0], SPOOF_VALUES[i][1]);
     }
     
     printf("\n");
     printf("  " BGREEN "[✓]" RESET " Run '" CYAN "sudo %s spoof" RESET "' to apply\n", PROGNAME);
     printf("  " BCYAN "[i]" RESET " Add '" CYAN "--stealth" RESET "' to hide spoofer processes\n");
     printf("\n");
     return 0;
 }
 
 static int cmd_status(int argc, char **argv)
 {
     (void)argc; (void)argv;
     
     print_banner_small();
     printf(BYELLOW "  [*] Scanning for VM indicators...\n\n" RESET);
     
     int vm_indicators = 0;
     int total_checks = 0;
     
     /* DMI values */
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
     
     /* MAC address */
     printf("\n" BOLD "  Network:\n" RESET);
     const char *net_paths[] = {
         "/sys/class/net/eth0/address",
         "/sys/class/net/enp0s3/address",
         "/sys/class/net/enp0s8/address",
         NULL
     };
     
     for (int i = 0; net_paths[i] != NULL; i++) {
         char *mac = read_file_line(net_paths[i]);
         if (mac) {
             total_checks++;
             char ifname[32];
             const char *p = net_paths[i] + 16;  /* Skip /sys/class/net/ */
             sscanf(p, "%[^/]", ifname);
             
             if (strncmp(mac, "08:00:27", 8) == 0) {
                 printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VirtualBox OUI" RESET "\n", ifname, mac);
                 vm_indicators++;
             } else {
                 printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", ifname, mac);
             }
         }
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
     char *disk_model = read_file_line("/sys/class/block/sda/device/model");
     if (disk_model) {
         total_checks++;
         if (is_vbox_string(disk_model)) {
             printf("      " RED "[✗]" RESET " %-16s " RED "%-20s" RESET " " DIM "← VM detected" RESET "\n", "disk model", disk_model);
             vm_indicators++;
         } else {
             printf("      " GREEN "[✓]" RESET " %-16s " GREEN "%s" RESET "\n", "disk model", disk_model);
         }
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
     bool specific_spoofers = false;
     bool stealth = false;
     bool enable_modules = false;
     
     /* Parse options */
     for (int i = 0; i < argc; i++) {
         if (strcmp(argv[i], "--stealth") == 0 || strcmp(argv[i], "-s") == 0) {
             stealth = true;
         } else if (strcmp(argv[i], "--modules") == 0) {
             enable_modules = true;
         } else if (strcmp(argv[i], "--dmi") == 0 ||
                    strcmp(argv[i], "--mac") == 0 ||
                    strcmp(argv[i], "--cpu") == 0 ||
                    strcmp(argv[i], "--mem") == 0 ||
                    strcmp(argv[i], "--pci") == 0 ||
                    strcmp(argv[i], "--disk") == 0) {
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
                     if (strcmp(spoofers[j].name, "dmi") == 0)
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
                     if (strcmp(spoofers[j].name, "disk") == 0)
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
     
     print_banner();
     
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
         const char *check_path = spoofers[i].binary;
         if (!file_exists(check_path)) {
             printf("      " RED "[✗]" RESET " %-12s " DIM "binary not found: %s" RESET "\n", 
                    spoofers[i].name, spoofers[i].binary);
             failed++;
             continue;
         }
         
         /* Launch it */
         if (launch_spoofer(&spoofers[i]) == 0) {
             printf("      " BGREEN "[✓]" RESET " %-12s %s\n", 
                    spoofers[i].name, spoofers[i].description);
             loaded++;
             usleep(50000);  /* 50ms between launches */
         } else {
             printf("      " RED "[✗]" RESET " %-12s " DIM "launch failed: %s" RESET "\n",
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
         printf("  " BCYAN "  ◉  Profile:" RESET " Dell OptiPlex 7090\n");
         if (stealth) {
             printf("  " BCYAN "  ◉  Stealth:" RESET " Processes hidden from /proc\n");
         }
         printf("\n");
         printf("      " DIM "Press Ctrl+C to stop all spoofers" RESET "\n");
         printf("\n");
         
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
     printf(BYELLOW "  [*] Stopping all spoofers...\n\n" RESET);
     
     const char *process_names[] = {
         "dmi_spoof", "cpuinfo_spoof", "meminfo_spoof", 
         "pci_spoof", "ioctl_spoof", "netlink_spoof",
         "pidhide", "textreplace", "modules_hide",
         "disk_spoof.sh",
         NULL
     };
     
     int stopped = 0;
     for (int i = 0; process_names[i] != NULL; i++) {
         char cmd[256];
         snprintf(cmd, sizeof(cmd), "pkill -9 '%s' 2>/dev/null", process_names[i]);
         if (system(cmd) == 0) {
             printf("      " GREEN "[✓]" RESET " Stopped: %s\n", process_names[i]);
             stopped++;
         }
     }
     
     if (stopped == 0) {
         printf("      " DIM "[*] No running spoofers found" RESET "\n");
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
     int pos = snprintf(cmd, sizeof(cmd), "./pidhide");
     
     if (pids) {
         char *copy = strdup(pids);
         char *tok = strtok(copy, ",");
         while (tok) {
             pos += snprintf(cmd + pos, sizeof(cmd) - pos, " -p %s", tok);
             printf("      " CYAN "→" RESET " PID: %s\n", tok);
             tok = strtok(NULL, ",");
         }
         free(copy);
     }
     
     if (names) {
         char *copy = strdup(names);
         char *tok = strtok(copy, ",");
         while (tok) {
             pos += snprintf(cmd + pos, sizeof(cmd) - pos, " -n %s", tok);
             printf("      " CYAN "→" RESET " Name: %s\n", tok);
             tok = strtok(NULL, ",");
         }
         free(copy);
     }
     
     if (hide_self) {
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
     
     /* Commands not requiring root */
     if (strcmp(cmd, "check") == 0) {
         return cmd_check(argc - 2, argv + 2);
     }
     
     /* Commands requiring root */
     if (!check_root()) {
         return 1;
     }
     
     if (strcmp(cmd, "spoof") == 0) {
         return cmd_spoof(argc - 2, argv + 2);
     }
     if (strcmp(cmd, "status") == 0) {
         return cmd_status(argc - 2, argv + 2);
     }
     if (strcmp(cmd, "stop") == 0) {
         return cmd_stop(argc - 2, argv + 2);
     }
     if (strcmp(cmd, "hide") == 0) {
         return cmd_hide(argc - 2, argv + 2);
     }
     
     fprintf(stderr, RED "  [!] Unknown command: %s\n" RESET, cmd);
     fprintf(stderr, DIM "      Run '%s --help' for usage\n" RESET, PROGNAME);
     return 1;
 }