# Januscape 热修复 — CVE-2026-53359

[English](README.md)

KVM/x86 shadow MMU 虚拟机逃逸漏洞。**大多数方案无需重启，零停机修复。**

| | 详情 |
|---|---|
| **CVE 编号** | CVE-2026-53359 |
| **原始 PoC** | [github.com/V4bel/Januscape](https://github.com/V4bel/Januscape) |
| **上游修复** | [commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)（2026-06-16 并入主线） |
| **影响范围** | Linux ≥ 2.6.35（2010 年）至未修复内核 |
| **影响** | 宿主机内核 panic (DoS) 或虚拟机逃逸 (RCE) |
| **触发条件** | 向虚拟机暴露了嵌套虚拟化 |
| **影响架构** | Intel VMX/EPT + AMD SVM/NPT（仅 x86） |

## 选择修复方案

| 方案 | 停机 | 内核版本 | 适用场景 |
|------|:---:|---------|---------|
| **[nested=0](docs/nested-disable.md)** | 重启或 KVM 重载 | 任意 | 无嵌套 VM 需求的 VPS — 最简单零风险 |
| **[ftrace 热修复](docs/ftrace-hotfix.md)** | **无** | ≥ 4.0 | 需要嵌套虚拟化、不能重启、一个 .ko 搞定 |
| **[kpatch (RHEL 8.x)](docs/kpatch-rhel8.md)** | **无** | 4.18 (RHEL 8) | RHEL 8.x 使用 `kvm_mmu_get_page` ABI |
| **[内核重编译](docs/manual-patch.md)** | 重启 | 任意 | 有维护窗口、希望永久修复 |

## 快速检测

```bash
# 内核是否有漏洞？
grep 'role.word' /proc/kallsyms || echo "需要修复"

# 嵌套虚拟化开了吗？
cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested

# 被攻击过吗？（崩溃取证）
bash tools/januscape-logcheck.sh
```

## 集群排查

```bash
# 逐台宿主机审计：
bash tools/januscape-check.sh
```

## QEMU 版本注意事项

QEMU 6.x 会部分屏蔽 PoC 的可利用性（L1 VM 先崩溃、宿主机未 panic），但
逃逸信号**已到达 L0 KVM**。
[实测证据](docs/ftrace-hotfix.md#qemu-版本与-poc-的可利用性)。
QEMU 不是安全边界——无论 QEMU 什么版本都应修补 KVM。

## 项目结构

```
├── kmod/                 # 内核模块（ftrace hook）
├── installer/            # Go 部署工具
├── docs/                 # 详细方案文档
│   ├── nested-disable.md
│   ├── ftrace-hotfix.md
│   ├── kpatch-rhel8.md
│   └── manual-patch.md
├── tools/                # 集群审计脚本
│   ├── januscape-check.sh
│   └── januscape-logcheck.sh
└── apply.sh              # Shell 部署（简易版）
```

## 许可证

GPL v2，详见 [COPYING](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/COPYING)。

**版权所有 (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD. & GEELINX LTD.**
联系方式：master@aoripus.com

## 参考资料

- [原始 PoC — V4bel/Januscape](https://github.com/V4bel/Januscape)
- [上游修复 — commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)
- [lore.kernel.org 补丁讨论](https://lore.kernel.org/all/20260617134425.440091-1-pbonzini@redhat.com/)
- [oss-security 公告](https://www.openwall.com/lists/oss-security/2026/07/06/1)
- [Google kvmCTF](https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing.html)
