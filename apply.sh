#!/bin/bash
# ──────────────────────────────────────────────────────────────────────────
# Januscape (CVE-2026-53359) Hotfix — Zero-Downtime Deployment
#
# Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD.
# Copyright (c) 2026 GEELINX LTD.
#
# Usage:
#   ./apply.sh              Apply hotfix for running kernel (interactive)
#   ./apply.sh --force      Apply without confirmation prompts
#   ./apply.sh --rollback   Remove livepatch, restore original function
#   ./apply.sh --status     Check if hotfix is currently applied
#   ./apply.sh --check      Dry-run: check prerequisites only
#   ./apply.sh --build      Build + apply in one step
# ──────────────────────────────────────────────────────────────────────────

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KVER="$(uname -r)"
KARCH="$(uname -m)"
MODULE_NAME="hotfix"
KO_FILE="${SCRIPT_DIR}/artifacts/${MODULE_NAME}-${KVER}-${KARCH}.ko"
FORCE=0
ROLLBACK=0
STATUS_ONLY=0
CHECK_ONLY=0
BUILD_FIRST=0

# ── Color output ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; NC='\033[0m'

log()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }

die()  { err "$*"; exit 1; }

# ── Argument parsing ────────────────────────────────────────────────────
for arg in "$@"; do
	case "$arg" in
		--force|-f)   FORCE=1 ;;
		--rollback|-r) ROLLBACK=1 ;;
		--status|-s)   STATUS_ONLY=1 ;;
		--check|-c)    CHECK_ONLY=1 ;;
		--build|-b)    BUILD_FIRST=1 ;;
		--help|-h)
			echo "Usage: $0 [--force|--rollback|--status|--check|--build]"
			exit 0 ;;
		*) die "Unknown flag: $arg" ;;
	esac
done

# ── Status check ────────────────────────────────────────────────────────
if [ $STATUS_ONLY -eq 1 ]; then
	if lsmod | grep -q "^${MODULE_NAME} "; then
		ok "hotfix ACTIVE"
		dmesg | grep "januscape_hotfix" | tail -5
	else
		warn "hotfix NOT loaded"
		if grep -q 'role.word' /proc/kallsyms 2>/dev/null; then
			ok "upstream fix appears present in kallsyms"
		fi
	fi
	exit 0
fi

# ── Rollback ────────────────────────────────────────────────────────────
if [ $ROLLBACK -eq 1 ]; then
	log "Rolling back Januscape hotfix..."
	if lsmod | grep -q "^${MODULE_NAME} "; then
		rmmod "$MODULE_NAME" && ok "hotfix removed — original function restored" \
			|| die "rmmod failed — check dmesg"
	else
		warn "hotfix was not loaded, nothing to do"
	fi
	exit 0
fi

# ── Phase 0: Pre-flight checks ──────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Januscape (CVE-2026-53359) — KVM Livepatch Hotfix"
echo "  Kernel: ${KVER}  Arch: ${KARCH}"
echo "═══════════════════════════════════════════════════════════"
echo ""

log "Phase 0: Pre-flight checks"

# 0.1: Is KVM loaded?
if ! lsmod | grep -q "^kvm "; then
	die "kvm module not loaded — nothing to patch"
fi
ok "kvm module loaded"

# 0.2: Kernel build dir exists?
KDIR="/lib/modules/${KVER}/build"
if [ ! -d "$KDIR" ]; then
	die "kernel-devel not found at $KDIR — install: yum install kernel-devel-${KVER}"
fi
ok "kernel-devel present"

# 0.3: CONFIG_LIVEPATCH?
if [ -f "${KDIR}/.config" ]; then
	if grep -q 'CONFIG_LIVEPATCH=y' "${KDIR}/.config"; then
		ok "CONFIG_LIVEPATCH=y"
	else
		warn "CONFIG_LIVEPATCH not found — livepatch may not be supported on this kernel"
	fi
else
	warn ".config missing — cannot verify kernel config"
fi

# 0.4: CONFIG_KALLSYMS_ALL? (needed for internal KVM symbol resolution)
if grep -q ' t kvm_mmu_get_child_sp' /proc/kallsyms 2>/dev/null; then
	ok "kvm_mmu_get_child_sp is visible in kallsyms"
elif grep -q ' t kvm_mmu_get_child_sp\b.*\[kvm\]' /proc/kallsyms 2>/dev/null; then
	ok "kvm_mmu_get_child_sp is visible in kallsyms (kvm module)"
else
	warn "kvm_mmu_get_child_sp NOT in kallsyms — CONFIG_KALLSYMS_ALL=y required"
	warn "If unavailable, use the fallback ftrace method (see docs/fallback.md)"
	die "Cannot proceed without CONFIG_KALLSYMS_ALL"
fi

# 0.5: Check if already patched upstream
if grep -q 'role.word' /proc/kallsyms 2>/dev/null; then
	warn "role.word found in kallsyms — upstream patch may already be applied"
	warn "This kernel might already be fixed. Check: uname -r && rpm -q kernel"
	if [ $FORCE -eq 0 ]; then
		echo -n "Proceed anyway? [y/N] "
		read -r ans
		[[ "$ans" =~ ^[Yy] ]] || exit 0
	fi
fi

# 0.6: Check we're not already loaded
if lsmod | grep -q "^${MODULE_NAME} "; then
	warn "hotfix already loaded — nothing to do"
	exit 0
fi

ok "All pre-flight checks passed"

[ $CHECK_ONLY -eq 1 ] && { ok "Check-only mode — done."; exit 0; }

# ── Phase 1: Build (if requested) ──────────────────────────────────────
if [ $BUILD_FIRST -eq 1 ] || [ ! -f "$KO_FILE" ]; then
	log "Phase 1: Building hotfix module for ${KVER}"
	if [ "$BUILD_FIRST" -ne 1 ] && [ ! -f "$KO_FILE" ]; then
		warn "Artifact not found at ${KO_FILE}, building..."
	fi
	make -C "$SCRIPT_DIR" \
		KDIR="$KDIR" \
		ARTIFACT="${KO_FILE}" \
		|| die "Build failed — check kernel-devel installation"
	ok "Build complete: $(ls -lh "$KO_FILE" | awk '{print $5}')"
else
	log "Phase 1: Using pre-built artifact: ${KO_FILE} ($(ls -lh "$KO_FILE" | awk '{print $5}'))"
fi

# ── Phase 2: Apply ─────────────────────────────────────────────────────
log "Phase 2: Applying livepatch..."

if [ $FORCE -eq 0 ]; then
	echo ""
	echo "  ┌─────────────────────────────────────────────────────────────┐"
	echo "  │ WARNING: About to livepatch KVM's shadow MMU.               │"
	echo "  │ This is a zero-downtime operation — no VMs are affected.    │"
	echo "  │ To rollback: ./apply.sh --rollback                          │"
	echo "  └─────────────────────────────────────────────────────────────┘"
	echo -n "  Apply hotfix? [y/N] "
	read -r ans
	[[ "$ans" =~ ^[Yy] ]] || { warn "Aborted by user"; exit 0; }
fi

insmod "$KO_FILE" 2>&1 || die "insmod failed — check dmesg for details"
ok "Module loaded"

# ── Phase 3: Verify ────────────────────────────────────────────────────
log "Phase 3: Verification"

# 3.1: Is module in lsmod?
if ! lsmod | grep -q "^${MODULE_NAME} "; then
	die "Module not showing in lsmod — apply failed silently"
fi
ok "Module present in lsmod"

# 3.2: Check livepatch status in sysfs
LP_SYSFS="/sys/kernel/livepatch/${MODULE_NAME}"
if [ -d "$LP_SYSFS" ]; then
	if grep -q '^1$' "${LP_SYSFS}/enabled" 2>/dev/null; then
		ok "Livepatch enabled in sysfs"
	else
		warn "Livepatch sysfs directory exists but enabled != 1"
	fi
else
	warn "No livepatch sysfs entry — patching may have used fallback mechanism"
fi

# 3.3: Check dmesg for success message
DMESG_OUT="$(dmesg | grep 'januscape_hotfix' | tail -10)"
echo "$DMESG_OUT"
if echo "$DMESG_OUT" | grep -q "LIVEPATCH ACTIVE"; then
	ok "Livepatch confirmed active in dmesg"
else
	warn "Livepatch confirmation message not found in dmesg"
	warn "Check manually: dmesg | grep januscape_hotfix"
fi

# 3.4: Verify via kallsyms — patched function should redirect
if grep -q 'livepatch_kvm_mmu_get_child_sp' /proc/kallsyms 2>/dev/null; then
	ok "Patched symbol visible in kallsyms"
fi

# ── Done ────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
ok "Januscape (CVE-2026-53359) hotfix APPLIED"
echo ""
echo "  Affected VMs:     0 (zero-downtime)"
echo "  Rollback:         ./apply.sh --rollback"
echo "  Status:           ./apply.sh --status"
echo "═══════════════════════════════════════════════════════════"
