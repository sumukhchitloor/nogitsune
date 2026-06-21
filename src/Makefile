# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Nogitsune - eBPF Anti-Sandbox Toolkit
# Based on bad-bpf by pathtofile

OUTPUT := .output
CLANG ?= clang
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL_SRC := $(abspath ../bpftool/src)
LIBBPF_OBJ := $(abspath $(OUTPUT)/libbpf.a)
BPFTOOL_OUTPUT ?= $(abspath $(OUTPUT)/bpftool)
BPFTOOL ?= $(BPFTOOL_OUTPUT)/bootstrap/bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/' \
			 | sed 's/arm.*/arm/' \
			 | sed 's/aarch64/arm64/' \
			 | sed 's/ppc64le/powerpc/' \
			 | sed 's/mips.*/mips/' \
			 | sed 's/riscv64/riscv/' \
			 | sed 's/loongarch64/loongarch/')
# vmlinux.h: auto-generated from running kernel's BTF, with checked-in fallback
VMLINUX_GEN      := $(OUTPUT)/vmlinux.h
VMLINUX_FALLBACK := ../vmlinux/$(ARCH)/vmlinux.h
VMLINUX          := $(VMLINUX_GEN)

# Includes
INCLUDES := -I$(OUTPUT) -I../libbpf/include/uapi -I$(dir $(VMLINUX))
CFLAGS := -g -Wall -std=gnu11
ALL_LDFLAGS := $(LDFLAGS) $(EXTRA_LDFLAGS)

# ============================================================================
# NOGITSUNE BUILD TARGETS
# ============================================================================

# BPF-based tools (have both .bpf.c and .c files)
BPF_APPS = pidhide textreplace ioctl_spoof netlink_spoof dmi_spoof meminfo_spoof cpuinfo_spoof modules_hide pci_spoof devicetree_spoof fshide uptime_spoof cpucount_spoof kmsg_spoof pathdeny

# Pure userspace CLI (no BPF code)
CLI_APPS = nogitsune

# All applications
APPS = $(BPF_APPS) $(CLI_APPS)

# ============================================================================

# Debug flag: make NOGITSUNE_DEBUG=1 for verbose BPF trace output
NOGITSUNE_DEBUG ?= 0

CLANG_BPF_SYS_INCLUDES ?= $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'					\
		      "$(1)"						\
		      "$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
		      "$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

define allow-override
  $(if $(or $(findstring environment,$(origin $(1))),\
            $(findstring command line,$(origin $(1)))),,\
    $(eval $(1) = $(2)))
endef

$(call allow-override,CC,$(CROSS_COMPILE)cc)
$(call allow-override,LD,$(CROSS_COMPILE)ld)

.PHONY: all
all: $(APPS)
	@echo ""
	@echo "╔═══════════════════════════════════════════════════════════╗"
	@echo "║         野狐 Nogitsune - Build Complete!                  ║"
	@echo "╠═══════════════════════════════════════════════════════════╣"
	@echo "║  Usage:                                                   ║"
	@echo "║    sudo ./nogitsune spoof        # Load all spoofers      ║"
	@echo "║    sudo ./nogitsune spoof --stealth  # + hide processes   ║"
	@echo "║    sudo ./nogitsune check        # Dry run                ║"
	@echo "║    sudo ./nogitsune status       # Show current values    ║"
	@echo "╚═══════════════════════════════════════════════════════════╝"

.PHONY: test-arch
test-arch:
	@echo "Architecture: $(ARCH)"
	@echo "Kernel: $$(uname -r)"
	@if [ -f /sys/kernel/btf/vmlinux ]; then \
		echo "[✓] BTF available — full CO-RE support"; \
	else \
		echo "[!] BTF not available — will use checked-in fallback vmlinux.h"; \
	fi
	@echo "[✓] Ready for cross-arch compilation"

.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT) $(OUTPUT)/libbpf $(BPFTOOL_OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Generate vmlinux.h from running kernel's BTF, fall back to checked-in copy
$(VMLINUX_GEN): | $(OUTPUT) $(BPFTOOL)
	$(Q)if $(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp 2>/dev/null; then \
		mv $@.tmp $@; \
		printf '  %-8s %s %s\n' VMLINUX "$(patsubst $(abspath $(OUTPUT))/%,%,$@)" "[✓] from running kernel (CO-RE)"; \
	elif [ -f $(VMLINUX_FALLBACK) ]; then \
		cp $(VMLINUX_FALLBACK) $@; \
		printf '  %-8s %s %s\n' VMLINUX "$(patsubst $(abspath $(OUTPUT))/%,%,$@)" "[!] BTF missing, using checked-in fallback"; \
	else \
		echo "  [✗] BTF unavailable and no fallback vmlinux.h — cannot build"; \
		exit 1; \
	fi

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

# Build bpftool
$(BPFTOOL): | $(BPFTOOL_OUTPUT)
	$(call msg,BPFTOOL,$@)
	$(Q)$(MAKE) ARCH= CROSS_COMPILE= OUTPUT=$(BPFTOOL_OUTPUT)/ -C $(BPFTOOL_SRC) bootstrap

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c $(LIBBPF_OBJ) $(wildcard %.h) $(VMLINUX) | $(OUTPUT) $(BPFTOOL)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH)		      \
		     -DNOGITSUNE_DEBUG=$(NOGITSUNE_DEBUG)			      \
		     $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES)		      \
		     -c $(filter %.c,$^) -o $(patsubst %.bpf.o,%.tmp.bpf.o,$@)
	$(Q)$(BPFTOOL) gen object $@ $(patsubst %.bpf.o,%.tmp.bpf.o,$@)

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT) $(BPFTOOL)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code for BPF apps (needs skeleton)
$(patsubst %,$(OUTPUT)/%.o,$(BPF_APPS)): %.o: %.skel.h

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@

# Build BPF application binaries (link with libbpf)
$(BPF_APPS): %: $(OUTPUT)/%.o $(LIBBPF_OBJ) | $(OUTPUT)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(ALL_LDFLAGS) -lelf -lz -o $@

# ============================================================================
# NOGITSUNE CLI - Pure userspace, no BPF
# ============================================================================
$(OUTPUT)/nogitsune.o: nogitsune.c cJSON.h $(wildcard *.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(OUTPUT)/cJSON.o: cJSON.c cJSON.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

nogitsune: $(OUTPUT)/nogitsune.o $(OUTPUT)/cJSON.o
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lm -o $@

# ============================================================================

# Install to /usr/local/bin
.PHONY: install
install: all
	@echo "Installing to /usr/local/bin..."
	$(Q)install -m 755 $(APPS) /usr/local/bin/
	@echo "Done!"

.PHONY: uninstall
uninstall:
	@echo "Removing from /usr/local/bin..."
	$(Q)rm -f $(addprefix /usr/local/bin/,$(APPS))

# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
