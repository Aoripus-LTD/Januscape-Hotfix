# Januscape (CVE-2026-53359) Universal KVM Hotfix — Build System
#
# Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
# Copyright (c) 2026 GEELINX LTD.
#
# Supports two build modes:
#   1. kernel-devel only (default)     — kallsyms-based, works everywhere
#   2. kernel-devel + linux-source     — native KVM types, best compatibility
#
# Usage:
#   make                          Build with kernel-devel only
#   make KSRC=/path/to/kernel     Build with full kernel source for KVM headers
#   make all-kernels              Build for all installed kernel-devel
#   make clean                    Remove build artifacts

obj-m := hotfix.o

KDIR           ?= /lib/modules/$(shell uname -r)/build
PWD            := $(shell pwd)
KVER           := $(shell uname -r)
KARCH          := $(shell uname -m)
ARTIFACT_DIR   ?= $(PWD)/artifacts
ARTIFACT       := $(ARTIFACT_DIR)/hotfix-$(KVER)-$(KARCH).ko

# Auto-detect linux-source
KSRC ?= $(shell \
  src="/usr/src/kernels/$(KVER)";          [ -f "$$src/arch/x86/kvm/mmu/mmu_internal.h" ] && echo "$$src" && exit; \
  src="/usr/src/linux-$(KVER)";            [ -f "$$src/arch/x86/kvm/mmu/mmu_internal.h" ] && echo "$$src" && exit; \
  for d in /usr/src/linux-source-* /usr/src/linux-*; do \
    [ -f "$$d/arch/x86/kvm/mmu/mmu_internal.h" ] && echo "$$d" && exit; \
  done)

ifneq ($(KSRC),)
  ccflags-y += -DHAS_KVM_SOURCE -I$(KSRC)/arch/x86/kvm -I$(KSRC)/arch/x86/kvm/mmu
  HAS_KVM_SRC := y
endif

ccflags-y += -Wall -Wno-declaration-after-statement

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
		grep -q 'CONFIG_LIVEPATCH=y' "$(KDIR)/.config" && echo "  CONFIG_LIVEPATCH: y" || echo "  WARNING: CONFIG_LIVEPATCH not set"; \
		grep -q 'CONFIG_KALLSYMS_ALL=y' "$(KDIR)/.config" && echo "  CONFIG_KALLSYMS_ALL: y" || echo "  WARNING: CONFIG_KALLSYMS_ALL not set"; \
	else \
		echo "  WARNING: no .config found at $(KDIR)"; \
	fi
ifneq ($(KSRC),)
	@echo "  KSRC: $(KSRC) — native KVM types enabled"
else
	@echo "  KSRC: not found — kallsyms fallback mode"
	@echo "  Install linux-source for best compatibility:"
	@echo "    RHEL/CentOS: yum install kernel-source-$(KVER)"
	@echo "    Debian/Ubuntu: apt install linux-source-$(KVER)"
endif

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
	@echo ">>> Load:   insmod hotfix"
	@echo ">>> Unload: echo 0 > /sys/kernel/livepatch/hotfix/enabled"

uninstall:
	rm -f /lib/modules/$(KVER)/extra/hotfix.ko
	depmod -a $(KVER) 2>/dev/null || true
	@echo ">>> Uninstalled for kernel $(KVER)"

clean:
	$(MAKE) -C "$(KDIR)" M="$(PWD)" clean
	rm -rf "$(ARTIFACT_DIR)"
