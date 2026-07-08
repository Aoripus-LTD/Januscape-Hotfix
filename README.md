# Januscape Hotfix — CVE-2026-53359

[简体中文](README.zh-CN.md)

Guest-to-host escape vulnerability in the KVM/x86 shadow MMU.
**Zero-downtime fixes available — no reboot required for most methods.**

| | Detail |
|---|---|
| **CVE** | CVE-2026-53359 |
| **Original PoC** | [github.com/V4bel/Januscape](https://github.com/V4bel/Januscape) |
| **Upstream fix** | [commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8) (merged 2026-06-16) |
| **Affected** | Linux ≥ 2.6.35 (2010) through pre-2026-06-16 kernels |
| **Impact** | Host kernel panic (DoS) or escape (RCE) |
| **Requires** | Nested virtualization exposed to guest |
| **Architectures** | Intel VMX/EPT + AMD SVM/NPT (x86 only) |

## Choose your fix

| Method | Downtime | Kernel | When to use |
|--------|:---:|--------|-------------|
| **[nested=0](docs/nested-disable.md)** | Reboot or KVM reload | Any | No nested-VM VPS — simplest, zero risk |
| **[ftrace hotfix](docs/ftrace-hotfix.md)** | **None** | ≥ 4.0 | Need nested virt, can't reboot, one `.ko` |
| **[kpatch (RHEL 8.x)](docs/kpatch-rhel8.md)** | **None** | 4.18 (RHEL 8) | RHEL 8.x with `kvm_mmu_get_page` ABI |
| **[kernel rebuild](docs/manual-patch.md)** | Reboot | Any | Maintenance window, permanent fix |

## Quick check

```bash
# Is my kernel vulnerable?
grep 'role.word' /proc/kallsyms || echo "NEEDS FIX"

# Is nested virtualization exposed?
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested

# Was I already attacked? (crash forensic)
bash tools/januscape-logcheck.sh
```

## Fleet triage

```bash
# Audit every host in your fleet:
bash tools/januscape-check.sh
```

## QEMU version caveat

QEMU 6.x partially masks PoC exploitability (VM crashes before host panic),
but the escape signal **reaches L0 KVM**.
[Evidence](docs/ftrace-hotfix.md#qemu-version--poc-exploitability).
QEMU is not a security boundary — patch KVM regardless.

## Project Structure

```
├── kmod/                 # Kernel module (ftrace hook)
├── installer/            # Go deployment tool
├── docs/                 # Detailed method docs
│   ├── nested-disable.md
│   ├── ftrace-hotfix.md
│   ├── kpatch-rhel8.md
│   └── manual-patch.md
├── tools/                # Fleet audit scripts
│   ├── januscape-check.sh
│   └── januscape-logcheck.sh
└── apply.sh              # Shell deploy (simple)
```

## License

GPL v2, as described in the [COPYING](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/COPYING) file.

**Copyright (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD. & GEELINX LTD.**
Contact: master@aoripus.com

## References

- [Original PoC — V4bel/Januscape](https://github.com/V4bel/Januscape)
- [Upstream fix — commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)
- [Patch on lore.kernel.org](https://lore.kernel.org/all/20260617134425.440091-1-pbonzini@redhat.com/)
- [oss-security disclosure](https://www.openwall.com/lists/oss-security/2026/07/06/1)
- [Google kvmCTF](https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing.html)
