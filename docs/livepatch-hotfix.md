# Livepatch Hotfix — 通用热修复

适用于 Linux **4.12**–6.x，所有发行版。通过内核 livepatch API 在线替换漏洞函数，
无需重启、无需迁移虚拟机。同时修复两个 commit：
- `81ccda30b4e8`（DoS 防护）
- `0cb2af2ea66ad`（UAF 逃逸链防护）

## 前置条件

- **Linux ≥ 4.12**（`CONFIG_LIVEPATCH` 自此版本稳定可用）
- **`CONFIG_LIVEPATCH=y`**（RHEL/CentOS 8+、Ubuntu 20.04+、Debian 11+ 默认开启）
- **`CONFIG_KALLSYMS_ALL=y`**（所有发行版内核默认开启）
- `kernel-devel` / `linux-headers` 匹配当前运行内核

验证：`grep CONFIG_LIVEPATCH /boot/config-$(uname -r)`

## 快速部署

### 预编译模块

```bash
insmod hotfix-$(uname -r)-x86_64.ko
dmesg | grep "PATCH ACTIVE"
rmmod hotfix   # 回滚
```

### 从源码编译

```bash
# RHEL / CentOS
yum install -y kernel-devel-$(uname -r) make gcc

# Debian / Ubuntu
apt install -y linux-headers-$(uname -r) build-essential

cd kmod && make && insmod hotfix.ko
```

### Go 安装器（集群部署）

```bash
cd installer && go build -o januscape-hotfix .
./januscape-hotfix check     # 前置检查
./januscape-hotfix deploy --force   # 自动检测、编译、加载、验证
./januscape-hotfix rollback  # 回滚
./januscape-hotfix status    # 状态
```

## 架构

## 架构

```
Go 安装器                             内核模块 (hotfix.ko)
detect offsets → make → insmod        klp_enable_patch() 替换两个函数
BTF → DWARF → DB → defaults           kallsyms_lookup_name 解析内部符号
                                      offset 偏移访问 KVM 结构体
```

## 兼容性

| 内核版本 | 状态 |
|---------|------|
| ≥ 4.12 | ✅ `CONFIG_LIVEPATCH` 稳定可用 |
| 4.0–4.11 | ⚠️ livepatch 存在但 API 不完全 |
| < 4.0 | ❌ 不支持 |

## 偏移量检测

```
BTF (bpftool) → DWARF (vmlinux debuginfo) → Offset Database → 默认值
```

| 字段 | 典型值 |
|-----|-------|
| `struct kvm_mmu_page → gfn` | `0x38` (6.x) / `0x30` (4.x) |
| `struct kvm_mmu_page → role.word` | `0x28` (6.x) / `0x20` (4.x) |

手动验证：`pahole -C kvm_mmu_page /usr/lib/debug/lib/modules/$(uname -r)/vmlinux | grep -E 'gfn|role'`

## 验证

```bash
lsmod | grep hotfix
dmesg | grep "PATCH ACTIVE"
grep januscape /proc/kallsyms
```

## 故障排查

| 症状 | 原因 | 解决 |
|-----|------|-----|
| `kvm_mmu_get_child_sp not in kallsyms` | `CONFIG_KALLSYMS_ALL` 未设置 | 检查内核配置 |
| `register_livepatch API_direct: -22` | 函数未找到或已修补 | `grep kvm_mmu_get_child_sp /proc/kallsyms` |
| `insmod: Unknown symbol` | KVM 未加载 | `modprobe kvm` |
| `gfn mismatch` in dmesg | 偏移量错误 | `insmod hotfix.ko gfn_off=0x?? role_off=0x??` |
| 模块加载但未生效 | KVM 在热修复后加载 | 卸载热修复→加载 KVM→重新加载热修复 |
| `kvm_mmu_get_page` unsupported | RHEL 8.x 4.18 内核 | 参见 [kpatch 方案](kpatch-rhel8.md) |

## 符号降级机制

部分内核（ELRepo 6.x on RHEL8、特定 Ubuntu 内核）将 KVM 内部辅助函数内联或重命名。
本模块自动处理：

- `is_shadow_present_pte` / `is_large_pte` / `spte_to_child_sp` → 内置 x86_64 PTE 位运算回退
- Shadow page 分配器 → 二进制扫描原始函数机器码提取目标地址（不猜函数名）
- RHEL 8.x `kvm_mmu_get_page` → 主动检测并拒绝加载（ABI 不兼容）

## QEMU 版本与 PoC 的可利用性

测试中发现 QEMU 版本影响 PoC 能否**完整触发宿主机 panic**，尽管漏洞信号总是到达内核。

| QEMU | PoC 行为 | 详情 |
|------|---------|------|
| **≥ 7.0** | 完全暴露 | 嵌套 VMX/SVM 透传成熟；PoC 触发宿主机 panic |
| **6.x** | 部分暴露 — VM 崩，宿主机存活 | 嵌套 VMX 操作**到达 L0 KVM**（dmesg 可见 `nested_vmx_load_cr3`），但 QEMU 先 abort 了 VM |
| **≤ 5.x** | 不太可能到达 | 嵌套 VMX 之前的 QEMU；L1 无法执行 `vmxon` |

**实测证据**（QEMU 6.2.0 EL8, L0 6.19.2-elrepo, L1 6.8.0-55-generic）：

```bash
# L1 VM: insmod poc.ko → step 4/4 → VM crash

# L0 host dmesg:
$ dmesg | grep 'nested_vmx\|vmx_handle_exit' | tail -3
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]   # ← ESCAPE SIGNAL
  vmx_handle_exit+0xe/0x40 [kvm_intel]            #   REACHED L0!
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]

$ uptime   # ← host stayed up, no panic
 18:23:41 up 7 days,  3:14
```

> QEMU 6.x abort 不是安全保障——信号已进入 KVM vulnerable path。不要将 QEMU 版本当作缓解层。
