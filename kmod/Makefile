# Januscape (CVE-2026-53359) Universal KVM Hotfix — Build System
#
# Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
# Copyright (c) 2026 GEELINX LTD.
#
# Builds a kernel module that livepatches kvm_mmu_get_child_sp()
# to add role.word comparison, fixing the shadow MMU use-after-free.
#
# Works on all Linux kernel trees >= 4.0 (tested: RHEL/CentOS/Debian/Ubuntu).
#
# Usage:
#   make                    Build for the running kernel
#   make KDIR=/path         Build for a specific kernel tree
#   make all-kernels        Build for all installed kernel-devel
#   make check              Verify build prerequisites (dry run)
#   make clean              Remove build artifacts

obj-m := hotfix.o

KDIR           ?= /lib/modules/$(shell uname -r)/build
PWD            := $(shell pwd)
KVER           := $(shell uname -r)
KARCH          := $(shell uname -m)
ARTIFACT_DIR   ?= $(PWD)/artifacts
ARTIFACT       := $(ARTIFACT_DIR)/hotfix-$(KVER)-$(KARCH).ko
OFFSETS_CFLAGS ?=

ccflags-y += $(OFFSETS_CFLAGS) -Wall -Wno-declaration-after-statement

.PHONY: all check artifact clean install uninstall all-kernels

# Default: check prerequisites, build the module, copy to artifacts/
all: check modules artifact

check:
	@echo ">>> Januscape hotfix build check <<<"
	@echo "  Kernel: $(KVER)  Arch: $(KARCH)"
	@if [ ! -d "$(KDIR)" ]; then \
		echo "  ERROR: kernel-devel not found at $(KDIR)"; \
		echo "  RHEL/CentOS: yum install kernel-devel-$(KVER)"; \
		echo "  Debian/Ubuntu: apt install linux-headers-$(KVER)"; \
		exit 1; \
	fi
	@if [ -f "$(KDIR)/.config" ]; then \
		if ! grep -q 'CONFIG_DYNAMIC_FTRACE=y' "$(KDIR)/.config"; then \
			echo "  WARNING: CONFIG_DYNAMIC_FTRACE not set — module may not work"; \
		else \
			echo "  CONFIG_DYNAMIC_FTRACE: y"; \
		fi; \
		if ! grep -q 'CONFIG_KALLSYMS_ALL=y' "$(KDIR)/.config"; then \
			echo "  WARNING: CONFIG_KALLSYMS_ALL not set — internal KVM symbols may be invisible"; \
		else \
			echo "  CONFIG_KALLSYMS_ALL: y"; \
		fi; \
	else \
		echo "  WARNING: no .config found at $(KDIR)"; \
	fi
	@echo "  gfn_offset hint (default):   0x38"
	@echo "  role_word_offset hint (default): 0x28"
	@echo "  Use the Go installer for automatic BTF/DWARF offset detection."

# Invoke kernel build system to compile hotfix.ko
modules:
	$(MAKE) -C "$(KDIR)" M="$(PWD)" modules

# Copy built module to artifacts directory
artifact:
	@mkdir -p "$(ARTIFACT_DIR)"
	@cp hotfix.ko "$(ARTIFACT)"
	@echo ">>> Artifact: $(ARTIFACT)"

# Build for all installed kernel-devel packages on this machine.
all-kernels:
	@found=0; \
	for kdir in /lib/modules/*/build; do \
		if [ -d "$$kdir" ] && [ -f "$$kdir/.config" ]; then \
			kv=$$(basename $$(dirname $$kdir)); \
			echo; \
			echo "===== Building for $$kv ====="; \
			$(MAKE) KDIR="$$kdir" KVER="$$kv" \
				ARTIFACT="$(ARTIFACT_DIR)/hotfix-$$kv-$(KARCH).ko" \
				modules \
				|| echo "WARNING: build failed for $$kv"; \
			found=1; \
		fi; \
	done; \
	if [ $$found -eq 0 ]; then \
		echo "No kernel-devel packages found in /lib/modules/*/build"; \
		exit 1; \
	fi
	@echo; \
	echo "===== All artifacts ====="; \
	ls -lh $(ARTIFACT_DIR)/ 2>/dev/null || echo "(none)"

check-only: check
	@echo ">>> Check passed — ready to build."

install: all
	@echo ">>> Installing for kernel $(KVER)..."
	@mkdir -p /lib/modules/$(KVER)/extra/
	cp hotfix.ko /lib/modules/$(KVER)/extra/
	@depmod -a $(KVER) 2>/dev/null || true
	@echo ">>> Installed: /lib/modules/$(KVER)/extra/hotfix.ko"
	@echo ">>> Load:   insmod hotfix gfn_off=0x38 role_off=0x28"
	@echo ">>> Unload: rmmod hotfix"

uninstall:
	rm -f /lib/modules/$(KVER)/extra/hotfix.ko
	depmod -a $(KVER) 2>/dev/null || true
	@echo ">>> Uninstalled for kernel $(KVER)"

clean:
	$(MAKE) -C "$(KDIR)" M="$(PWD)" clean
	rm -rf "$(ARTIFACT_DIR)"
