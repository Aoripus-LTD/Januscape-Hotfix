# Januscape Hotfix — CVE-2026-53359

[简体中文](README.zh-CN.md)

Zero-downtime livepatch for **CVE-2026-53359 (Januscape)**, a guest-to-host
escape vulnerability in the KVM/x86 shadow MMU.

**Applies the upstream fix without rebooting or migrating VMs.**

- [Overview](#overview)
  - [What this hotfix does](#what-this-hotfix-does)
  - [How to verify if your kernel is vulnerable](#how-to-verify-if-your-kernel-is-vulnerable)
- [Deployment](#deployment)
  - [Option A: One-click hotfix](#option-a-one-click-hotfix-recommended-zero-downtime)
  - [Option B: Manual kernel patching](#option-b-manual-kernel-patching-compile-a-new-kernel)
- [Architecture](#architecture)
- [Requirements](#requirements)
  - [Host kernel](#host-kernel)
  - [Build host](#build-host)
  - [Guest (attack surface)](#guest-attack-surface)
  - [QEMU version & PoC exploitability](#qemu-version--poc-exploitability)
- [Go Installer Reference](#go-installer-reference)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Project Structure](#project-structure)
- [License](#license)
- [References](#references)

## Overview

Januscape is a **use-after-free** in `kvm_mmu_get_child_sp()` that allows a
KVM guest to:

- **DoS**: panic the host kernel, taking all co-located VMs down
- **Escape**: achieve code execution on the host (full escape exploit exists
  but is not yet publicly released)

The bug was latent for **16 years** (all kernels from 2010 to June 2026).
It affects both Intel (VMX/EPT) and AMD (SVM/NPT) — the first confirmed
cross-architecture KVM escape.

| | Detail |
|---|---|
| **CVE** | CVE-2026-53359 |
| **Original PoC** | [github.com/V4bel/Januscape](https://github.com/V4bel/Januscape) |
| **Upstream fix** | [commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8) (merged 2026-06-16, mainline) |
| **Affected** | Linux ≥ 2.6.35 (2010-08-01) up to pre-81ccda30b4e8 kernels |
| **Patched since** | Mainline ≥ 2026-06-16; check `grep 'role.word' /proc/kallsyms` |
| **Trigger** | Nested virtualization (L1 runs L2 with raw VMX/SVM) |
| **Privilege** | Guest root (standard for cloud instances) |
| **Architectures** | Intel VMX/EPT + AMD SVM/NPT (x86 only, arm64 not affected) |

### What this hotfix does

The fix adds **one condition** to the shadow page reuse check:

```c
// Before (vulnerable): reuses page if gfn matches only
if (... && spte_to_child_sp(*sptep)->gfn == gfn)

// After (fixed): also requires the role to match
if (... && spte_to_child_sp(*sptep)->gfn == gfn
       && spte_to_child_sp(*sptep)->role.word == role.word)
```

This prevents a direct-split shadow page from being incorrectly reused for
an indirect shadow walk, which corrupts the reverse map and creates a
use-after-free.

### How to verify if your kernel is vulnerable

```bash
# If this returns empty, your kernel is NOT upstream-patched and needs the hotfix.
grep 'role.word' /proc/kallsyms
```

## Deployment

### Option A: One-click hotfix (recommended, zero downtime)

This is the livepatch approach — apply the fix to a running kernel without
rebooting or migrating VMs.

#### Pre-built artifact (same kernel version)

```bash
# Load the hotfix (zero-downtime, no VM interruption)
insmod hotfix-$(uname -r)-x86_64.ko

# Verify
dmesg | grep "PATCH ACTIVE"

# Rollback (restore original function)
rmmod hotfix
```

#### Build from source on target host

```bash
# RHEL / CentOS
yum install -y kernel-devel-$(uname -r) make gcc

# Debian / Ubuntu
apt install -y linux-headers-$(uname -r) build-essential

# Build and load
cd kmod && make && insmod hotfix.ko
```

#### Go installer (recommended for fleet deployment)

```bash
cd installer
go build -o januscape-hotfix .

# Check prerequisites only
./januscape-hotfix check

# Deploy (auto-detects offsets, builds, loads, verifies)
./januscape-hotfix deploy --force

# Rollback
./januscape-hotfix rollback
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Go Installer                        │
│  detect offsets → build kmod → insmod → verify      │
│  (BTF → DWARF → DB → default)                       │
└────────────────────┬────────────────────────────────┘
                     │ gfn_off=0x38 role_off=0x28
                     ▼
┌─────────────────────────────────────────────────────┐
│               Kernel Module (hotfix.ko)              │
│                                                     │
│  Hook kvm_mmu_get_child_sp() via ftrace:             │
│    Priority 1: register_ftrace_direct()  [5.11+]    │
│    Priority 2: ftrace IPMODIFY + SAVE_REGS [4.0+]   │
│                                                     │
│  Resolve internal KVM symbols at load time:          │
│    kallsyms_lookup_name (direct or kprobe fallback)  │
└─────────────────────────────────────────────────────┘
```

### Hook mechanism selection

| Kernel | Method | Reliability |
|--------|--------|-------------|
| ≥ 5.14 | `register_ftrace_direct(ops, addr)` | Best — direct call trampoline |
| 5.11–5.13 | `register_ftrace_direct(ip, addr)` | Good — direct call trampoline (old API) |
| 4.0–5.10 | ftrace IPMODIFY + SAVE_REGS | Good — IP redirect via ftrace handler |
| < 4.0 | Not supported | Requires `CONFIG_DYNAMIC_FTRACE_WITH_REGS` |

### kallsyms_lookup_name resolution

| Kernel | Method |
|--------|--------|
| < 5.7 | `__symbol_get("kallsyms_lookup_name")` — exported |
| ≥ 5.7 | kprobe on `kallsyms_lookup_name` — unexported, steals address |

## Requirements

### Host kernel

- **Linux ≥ 4.0** (for `FTRACE_OPS_FL_IPMODIFY`)
- **`CONFIG_DYNAMIC_FTRACE=y`** (default on all distro kernels)
- **`CONFIG_KALLSYMS_ALL=y`** (default on RHEL/CentOS/Debian/Ubuntu)
- **`CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`** (for < 5.11 kernels)

### Build host

- `kernel-devel` / `linux-headers` matching **target** kernel
- `gcc`, `make`
- `bpftool` (optional — for automatic offset detection)

### Guest (attack surface)

- Nested virtualization exposed to guest (`kvm_intel.nested=1` or `kvm_amd.nested=1`)
- Guest has root (standard for cloud instances)

### QEMU version & PoC exploitability

An unexpected finding during testing: QEMU version affects whether the PoC
can **fully trigger the host panic**, even though the vulnerability signal
always reaches the kernel.

| QEMU version | PoC behavior | Details |
|---|---|---|
| **≥ 7.0** | Full exposure — PoC triggers host panic | Nested VMX/SVM pass-through is mature; L1's `vmxon`/`vmrun` reaches the vulnerable KVM shadow MMU path and wins the race. |
| **6.x** | Partial exposure — VM crashes, host survives | PoC's nested VMX operations **do reach L0 KVM** (`dmesg` shows `nested_vmx_load_cr3` / `vmx_handle_exit`), proving the escape signal traverses the boundary. But QEMU 6.x's incomplete nested VMX emulation aborts the L1 VM before the race condition on L0 can be won. |
| **≤ 5.x** | Unlikely to reach vulnerable path | Pre-nested-VMX era QEMU; L1 cannot execute `vmxon` at all. |

**Evidence** — tested on QEMU 6.2.0 (EL8), L0 kernel 6.19.2-elrepo, L1
kernel 6.8.0-55-generic (Ubuntu 24.04):

```bash
# ── L1 (test VM) ──
$ dmidecode -s system-product-name
KVM                                     # ← confirmed: this is a VM

$ grep -E 'vmx|vmcs|shadow' /proc/cpuinfo | head -3
vmx flags: vnmi preemption_timer posted_intr invvpid ept_x_only ept_ad
           ept_1gb flexpriority apicv tsc_offset vtpr mtf vapic ept vpid
           unrestricted_guest vapic_reg vid shadow_vmcs pml tsc_scaling
                                        # ← nested VMX features present

$ sudo rmmod kvm_intel && sudo modprobe kvm_intel nested=1
$ lsmod | grep kvm
kvm_intel  487424  0                   # ← nested KVM works inside the VM
kvm       1404928  1 kvm_intel

$ cd Januscape-main && make && sudo rmmod kvm_intel && sudo insmod poc.ko
[*] poc step 1/4: backend=VMX/EPT ready
[*] poc step 2/4: nested page tables + L3 guest image built
[*] poc step 3/4: launching 8 kthreads (1 writer + 7 faulters)
[*] poc step 4/4: race live -- host DoS triggering
                                        # ← VM crashes shortly after
                                        #    SSH connection lost

# ── L0 (host) ──
$ qemu-system-x86_64 --version
QEMU emulator version 6.2.0            # ← QEMU 6.x

$ dmesg | grep 'nested_vmx\|vmx_handle_exit' | tail -5
  ? vmx_get_segment+0xc5/0x130 [kvm_intel]
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]   # ← ESCAPE SIGNAL REACHED
  vmx_handle_exit+0xe/0x40 [kvm_intel]            #    L0 KVM!
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]
  vmx_handle_exit+0xe/0x40 [kvm_intel]

$ uptime                                  # ← host stayed up, no panic
 18:23:41 up 7 days,  3:14,  1 user
```

> **Key takeaway**: The escape signal (`nested_vmx_load_cr3` →
> `vmx_handle_exit`) demonstrably reaches L0 KVM. QEMU 6.x aborts the L1
> VM *after* the boundary is crossed, but the vulnerable code path in KVM
> was already entered.

> **Important**: QEMU 6.x aborting the VM is **not a security guarantee** —
> the vulnerability signal demonstrably reaches the host KVM. A more
> sophisticated exploit (or a different nested VMX trigger sequence) could
> still win the race on pre-7.x QEMU. Do not rely on QEMU version as a
> mitigation layer.

## Go Installer Reference

```
januscape-hotfix <command> [flags]

Commands:
  deploy       Detect, build, and apply the hotfix
  check        Dry-run: validate prerequisites only
  rollback     Remove the hotfix (rmmod)
  status       Show current hotfix state
  build        Build kernel module only (no deploy)

Flags:
  --force, -f  Skip confirmation prompts
  --all        Build for all installed kernel-devel packages
```

### Offset detection priority

```
BTF (bpftool) → DWARF (vmlinux debuginfo) → Offset Database → Defaults
```

These struct field offsets are needed for `struct kvm_mmu_page`:

| Field | Typical Offset | Meaning |
|-------|---------------|---------|
| `gfn` | `0x38` (6.x) / `0x30` (4.x) | Guest frame number |
| `role.word` | `0x28` (6.x) / `0x20` (4.x) | Shadow page role |

To verify on your kernel:
```bash
pahole -C kvm_mmu_page /usr/lib/debug/lib/modules/$(uname -r)/vmlinux \
  | grep -E 'gfn|role'
```

## Shell Script (Simple Alternative)

```bash
# Quick deploy without Go
./apply.sh              # Interactive deploy
./apply.sh --force      # Non-interactive
./apply.sh --rollback   # Remove hotfix
./apply.sh --status     # Check state
./apply.sh --check      # Prerequisites only
```

### Option B: Manual kernel patching (compile a new kernel)

If you prefer a permanent fix through a kernel rebuild rather than a live
module, apply the upstream patch directly to your kernel source tree:

```bash
# 1. Download and apply the upstream fix
cd /path/to/linux-source
curl -L 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=81ccda30b4e8' | patch -p1

# 2. Verify the change (only one file, 6 insertions, 4 deletions)
git diff arch/x86/kvm/mmu/mmu.c

# 3. Rebuild and install your kernel per your distribution's process
# (RHEL/CentOS: make rpm-pkg; Debian/Ubuntu: make bindeb-pkg)
```

The complete fix is a 10-line diff:

```diff
--- a/arch/x86/kvm/mmu/mmu.c
+++ b/arch/x86/kvm/mmu/mmu.c
-	union kvm_mmu_page_role role;
+	union kvm_mmu_page_role role = kvm_mmu_child_role(sptep, direct, access);

-	if (is_shadow_present_pte(*sptep) && !is_large_pte(*sptep) &&
-	    spte_to_child_sp(*sptep) && spte_to_child_sp(*sptep)->gfn == gfn)
+	if (is_shadow_present_pte(*sptep) &&
+	    !is_large_pte(*sptep) &&
+	    spte_to_child_sp(*sptep) &&
+	    spte_to_child_sp(*sptep)->gfn == gfn &&
+	    spte_to_child_sp(*sptep)->role.word == role.word)
 		return ERR_PTR(-EEXIST);

-	role = kvm_mmu_child_role(sptep, direct, access);
 	return kvm_mmu_get_shadow_page(vcpu, gfn, role);
```

> **Note**: The Go installer and `apply.sh` are convenience tools provided
> **as-is, without warranty**. They have been tested on common RHEL/CentOS/
> Debian/Ubuntu kernel configurations with `CONFIG_DYNAMIC_FTRACE=y` and
> `CONFIG_KALLSYMS_ALL=y`. Validate in your own staging environment before
> production deployment. For mission-critical systems, the manual kernel
> rebuild (Option B) may be preferred.

## Verification

```bash
# 1. Module loaded
lsmod | grep hotfix

# 2. Livepatch active in dmesg
dmesg | grep "PATCH ACTIVE"

# 3. Sysfs livepatch (if using livepatch API)
cat /sys/kernel/livepatch/hotfix/enabled

# 4. Patched symbol in kallsyms
grep januscape /proc/kallsyms
```

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `kvm_mmu_get_child_sp not in kallsyms` | `CONFIG_KALLSYMS_ALL` not set | Check kernel config; use kprobe-only fallback |
| `register_ftrace_direct: -22` | Function not found or already patched | Verify `grep kvm_mmu_get_child_sp /proc/kallsyms` |
| `insmod: Unknown symbol` | KVM module not loaded | `modprobe kvm` first |
| `gfn mismatch` in dmesg after load | Wrong struct offsets | Manually specify: `insmod hotfix.ko gfn_off=0x?? role_off=0x??` |
| Module loads but livepatch not active | KVM loaded after hotfix | Unload hotfix, load KVM, reload hotfix |
| `kernel-devel` not found | Missing headers | Install matching `kernel-devel-$(uname -r)` |

## FAQ

### Do I need to reboot?

**No.** This is a livepatch. Apply with `insmod`, remove with `rmmod`.
No VMs are interrupted.

### Does this affect running VMs?

**No.** The fix only changes the shadow page reuse logic for *future*
shadow MMU walks. Existing shadow pages are not touched.

### What about kernels < 4.0?

Not supported. Kernels before 4.0 lack `FTRACE_OPS_FL_IPMODIFY`. If you
still run RHEL 7 (3.10), you need a `text_poke`-based approach (separate
project) or a kernel upgrade.

### Is arm64 affected?

**No.** Januscape (CVE-2026-53359) is x86-only. However, arm64 KVM hosts
should check for the separate [ITScape (CVE-2026-46316)](https://github.com/V4bel/ITScape)
vulnerability.

### What if my kernel already has the upstream fix?

The installer detects this:
```bash
grep 'role.word' /proc/kallsyms && echo "Already patched"
```

### Can I build once and deploy to many machines?

Yes. Build on a host with matching kernel-devel:
```bash
cd kmod && make KDIR=/path/to/target-kernel-headers
# Distribute hotfix.ko to identical-kernel hosts
```

Or use `make all-kernels` to build for all installed kernel versions.

### QEMU 6.x partially masks the PoC — am I safe?

**No.** The PoC's nested VMX signal reaches the host KVM even on QEMU 6.x
(confirmed via `dmesg` showing `nested_vmx_load_cr3` traces). The VM
crashes because QEMU 6.x's nested VMX emulation is incomplete, but the
escape signal already crossed the boundary into the vulnerable KVM path.
A more sophisticated trigger sequence could win the race regardless of
QEMU version. Upgrade QEMU and patch KVM — do not treat either as a
substitute for the other.

## Project Structure

```
.
├── kmod/
│   ├── hotfix.c              # Universal kernel module (4.x–6.x)
│   ├── offsets_db.h          # Struct offset database (fallback)
│   └── Makefile              # Kernel module build system
├── installer/
│   ├── main.go               # Go installer (deploy/check/rollback/status)
│   └── go.mod                # Go module definition
├── apply.sh                  # Shell-based deploy alternative
├── .gitignore
└── README.md
```

## License

GPL v2, as described in the [COPYING](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/COPYING) file of the Linux kernel source tree.

**Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD. & GEELINX LTD.**
Contact: master@aoripus.com

## References

- [Original PoC — V4bel/Januscape](https://github.com/V4bel/Januscape)
- [Upstream fix — commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)
- [Patch on lore.kernel.org](https://lore.kernel.org/all/20260617134425.440091-1-pbonzini@redhat.com/)
- [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/07/06/1)
- [Google kvmCTF](https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing.html)
