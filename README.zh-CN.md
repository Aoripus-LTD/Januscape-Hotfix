# Januscape 热修复 — CVE-2026-53359

[English](README.md)

针对 **CVE-2026-53359（Januscape）** 的零停机实时补丁——KVM/x86 shadow MMU
中的虚拟机逃逸漏洞。

**无需重启、无需迁移虚拟机，直接修补运行中的内核。**

## 概述

Januscape 是 `kvm_mmu_get_child_sp()` 中的一个 **UAF（释放后使用）** 漏洞，
允许 KVM 虚拟机：

- **拒绝服务（DoS）**：引发宿主机内核 panic，导致同一物理机上所有租户 VM 全部瘫痪
- **虚拟机逃逸**：在宿主机上执行任意代码（完整逃逸利用代码已存在但尚未公开）

该漏洞潜伏了 **16 年**（2010 年至 2026 年 6 月），同时影响 Intel（VMX/EPT）
和 AMD（SVM/NPT）——是首个已确认的跨架构 KVM 逃逸漏洞。

| | 详情 |
|---|---|
| **CVE 编号** | CVE-2026-53359 |
| **原始 PoC** | [github.com/V4bel/Januscape](https://github.com/V4bel/Januscape) |
| **上游修复** | [commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)（2026-06-16 并入主线） |
| **影响范围** | Linux ≥ 2.6.35（2010-08-01）至未包含 81ccda30b4e8 的内核 |
| **已修复版本** | 主线 ≥ 2026-06-16；执行 `grep 'role.word' /proc/kallsyms` 确认 |
| **触发条件** | 嵌套虚拟化（L1 使用裸 VMX/SVM 运行 L2） |
| **所需权限** | 虚拟机 root 权限（公有云实例通用条件） |
| **影响架构** | Intel VMX/EPT + AMD SVM/NPT（仅 x86，arm64 不受影响） |

### 本热修复做了什么

修复在 shadow page 复用检查中**新增一个条件**：

```c
// 修复前（存在漏洞）：仅比较 gfn 就复用
if (... && spte_to_child_sp(*sptep)->gfn == gfn)

// 修复后（安全）：同时要求 role 匹配
if (... && spte_to_child_sp(*sptep)->gfn == gfn
       && spte_to_child_sp(*sptep)->role.word == role.word)
```

这阻止了直接拆分页（direct split page）被错误复用于间接影子遍历（indirect
shadow walk），从而避免反向映射（reverse map）损坏和 UAF。

### 如何检查你的内核是否存在漏洞

```bash
# 如果返回空，说明内核未包含上游补丁，需要安装本热修复
grep 'role.word' /proc/kallsyms
```

## 部署

### 方案 A：一键热修复（推荐，零停机）

这是热补丁方案——在不重启、不迁移虚拟机的情况下将修复应用于运行中的内核。

#### 预构建模块（相同内核版本）

```bash
# 加载热修复（零停机，不影响任何虚拟机）
insmod hotfix-$(uname -r)-x86_64.ko

# 验证
dmesg | grep "PATCH ACTIVE"

# 回滚（恢复原始函数）
rmmod hotfix
```

#### 在目标主机上从源码编译

```bash
# RHEL / CentOS
yum install -y kernel-devel-$(uname -r) make gcc

# Debian / Ubuntu
apt install -y linux-headers-$(uname -r) build-essential

# 编译并加载
cd kmod && make && insmod hotfix.ko
```

#### Go 安装器（推荐用于集群部署）

```bash
cd installer
go build -o januscape-hotfix .

# 仅检查前置条件
./januscape-hotfix check

# 部署（自动检测偏移量、编译、加载、验证）
./januscape-hotfix deploy --force

# 回滚
./januscape-hotfix rollback
```

## 架构

```
┌─────────────────────────────────────────────────────┐
│                  Go 安装器                            │
│  检测偏移量 → 编译 kmod → insmod → 验证              │
│  (BTF → DWARF → 数据库 → 默认值)                    │
└────────────────────┬────────────────────────────────┘
                     │ gfn_off=0x38 role_off=0x28
                     ▼
┌─────────────────────────────────────────────────────┐
│               内核模块 (hotfix.ko)                    │
│                                                     │
│  通过 ftrace Hook kvm_mmu_get_child_sp()：           │
│    优先级 1：register_ftrace_direct()  [5.11+]      │
│    优先级 2：ftrace IPMODIFY + SAVE_REGS [4.0+]     │
│                                                     │
│  运行时解析 KVM 内部符号：                            │
│    kallsyms_lookup_name（直接调用或 kprobe 降级）     │
└─────────────────────────────────────────────────────┘
```

### Hook 机制选择

| 内核版本 | 方法 | 可靠性 |
|---------|------|--------|
| ≥ 5.14 | `register_ftrace_direct(ops, addr)` | 最佳 — 直接调用跳板 |
| 5.11–5.13 | `register_ftrace_direct(ip, addr)` | 良好 — 直接调用跳板（旧 API） |
| 4.0–5.10 | ftrace IPMODIFY + SAVE_REGS | 良好 — 通过 ftrace 处理程序重定向 IP |
| < 4.0 | 不支持 | 需要 `CONFIG_DYNAMIC_FTRACE_WITH_REGS` |

### kallsyms_lookup_name 解析方式

| 内核版本 | 方法 |
|---------|------|
| < 5.7 | `__symbol_get("kallsyms_lookup_name")` — 已导出 |
| ≥ 5.7 | 对 `kallsyms_lookup_name` 使用 kprobe — 未导出，偷取地址 |

## 系统要求

### 宿主机内核

- **Linux ≥ 4.0**（需要 `FTRACE_OPS_FL_IPMODIFY`）
- **`CONFIG_DYNAMIC_FTRACE=y`**（所有发行版内核默认开启）
- **`CONFIG_KALLSYMS_ALL=y`**（RHEL/CentOS/Debian/Ubuntu 默认开启）
- **`CONFIG_DYNAMIC_FTRACE_WITH_REGS=y`**（< 5.11 内核需要）

### 编译环境

- 与**目标**内核版本匹配的 `kernel-devel` / `linux-headers`
- `gcc`、`make`
- `bpftool`（可选 — 用于自动偏移量检测）

### 虚拟机（攻击面）

- 向虚拟机暴露了嵌套虚拟化（`kvm_intel.nested=1` 或 `kvm_amd.nested=1`）
- 虚拟机拥有 root 权限（公有云实例通用条件）

### QEMU 版本与 PoC 的可利用性

测试中发现的意外现象：即使漏洞信号始终能到达内核，QEMU 版本会影响 PoC
能否**完全触发宿主机 panic**。

| QEMU 版本 | PoC 行为 | 详情 |
|---|---|---|
| **≥ 7.0** | 完全暴露 — PoC 触发宿主机 panic | 嵌套 VMX/SVM 透传成熟；L1 的 `vmxon`/`vmrun` 到达存在漏洞的 KVM shadow MMU 路径并赢得竞争。 |
| **6.x** | 部分暴露 — 虚拟机崩溃，宿主机存活 | PoC 的嵌套 VMX 操作**确实到达了 L0 KVM**（`dmesg` 中可见 `nested_vmx_load_cr3` / `vmx_handle_exit`），证明了逃逸信号越过了边界。但 QEMU 6.x 不完整的嵌套 VMX 模拟在 L0 上赢得竞争之前就将 L1 VM abort 了。 |
| **≤ 5.x** | 不太可能到达漏洞路径 | 嵌套 VMX 出现之前的 QEMU 时代；L1 根本无法执行 `vmxon`。 |

**实测证据** — 测试环境：QEMU 6.2.0（EL8），L0 内核 6.19.2-elrepo，L1
内核 6.8.0-55-generic（Ubuntu 24.04）：

```bash
# ── L1（测试虚拟机）──
$ dmidecode -s system-product-name
KVM                                     # ← 确认：这是一台虚拟机

$ grep -E 'vmx|vmcs|shadow' /proc/cpuinfo | head -3
vmx flags: vnmi preemption_timer posted_intr invvpid ept_x_only ept_ad
           ept_1gb flexpriority apicv tsc_offset vtpr mtf vapic ept vpid
           unrestricted_guest vapic_reg vid shadow_vmcs pml tsc_scaling
                                        # ← 嵌套 VMX 特性已就绪

$ sudo rmmod kvm_intel && sudo modprobe kvm_intel nested=1
$ lsmod | grep kvm
kvm_intel  487424  0                   # ← 虚拟机内嵌套 KVM 正常工作
kvm       1404928  1 kvm_intel

$ cd Januscape-main && make && sudo rmmod kvm_intel && sudo insmod poc.ko
[*] poc step 1/4: backend=VMX/EPT ready
[*] poc step 2/4: nested page tables + L3 guest image built
[*] poc step 3/4: launching 8 kthreads (1 writer + 7 faulters)
[*] poc step 4/4: race live -- host DoS triggering
                                        # ← 虚拟机随即崩溃
                                        #    SSH 连接中断

# ── L0（宿主机）──
$ qemu-system-x86_64 --version
QEMU emulator version 6.2.0            # ← QEMU 6.x

$ dmesg | grep 'nested_vmx\|vmx_handle_exit' | tail -5
  ? vmx_get_segment+0xc5/0x130 [kvm_intel]
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]   # ← 逃逸信号已到达
  vmx_handle_exit+0xe/0x40 [kvm_intel]            #    L0 KVM！
  ? nested_vmx_load_cr3+0xab/0x160 [kvm_intel]
  vmx_handle_exit+0xe/0x40 [kvm_intel]

$ uptime                                  # ← 宿主机存活，未 panic
 18:23:41 up 7 days,  3:14,  1 user
```

> **关键结论**：逃逸信号（`nested_vmx_load_cr3` → `vmx_handle_exit`）可
> 证实地到达了 L0 KVM。QEMU 6.x 在越过边界**之后**才 abort 了 L1 VM，
> 但 KVM 中存在的漏洞代码路径已经在执行。

> **重要**：QEMU 6.x abort 虚拟机**不是安全保障**——漏洞信号已证实到达
> 宿主机 KVM。更精巧的利用方式（或其他嵌套 VMX 触发序列）仍可能在 7.x
> 之前的 QEMU 上赢得竞争。请勿将 QEMU 版本视为缓解措施。

## Go 安装器参考

```
januscape-hotfix <命令> [参数]

命令：
  deploy       检测、编译并安装热修复
  check        仅试运行：验证前置条件
  rollback     卸载热修复（rmmod）
  status       显示当前热修复状态
  build        仅编译内核模块（不部署）

参数：
  --force, -f  跳过确认提示
  --all        为所有已安装的 kernel-devel 包编译
```

### 偏移量检测优先级

```
BTF (bpftool) → DWARF (vmlinux 调试信息) → 偏移量数据库 → 默认值
```

`struct kvm_mmu_page` 需要以下结构体字段偏移量：

| 字段 | 典型偏移值 | 含义 |
|-----|----------|------|
| `gfn` | `0x38`（6.x）/ `0x30`（4.x） | 虚拟机物理帧号 |
| `role.word` | `0x28`（6.x）/ `0x20`（4.x） | shadow page 角色 |

在目标内核上验证：
```bash
pahole -C kvm_mmu_page /usr/lib/debug/lib/modules/$(uname -r)/vmlinux \
  | grep -E 'gfn|role'
```

## Shell 脚本（简易替代方案）

```bash
# 无需 Go 环境的快速部署
./apply.sh              # 交互式部署
./apply.sh --force      # 非交互模式
./apply.sh --rollback   # 卸载热修复
./apply.sh --status     # 检查状态
./apply.sh --check      # 仅检查前置条件
```

### 方案 B：手动内核补丁（编译新内核）

如果不使用热补丁模块，希望将修复永久内建于内核，则可直接将上游补丁应用到
内核源码树：

```bash
# 1. 下载并应用上游修复
cd /path/to/linux-source
curl -L 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=81ccda30b4e8' | patch -p1

# 2. 验证变更（仅一个文件，6 行添加，4 行删除）
git diff arch/x86/kvm/mmu/mmu.c

# 3. 按发行版流程重新编译并安装内核
# （RHEL/CentOS：make rpm-pkg；Debian/Ubuntu：make bindeb-pkg）
```

完整修复仅有 10 行 diff：

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

> **注意**：Go 安装器和 `apply.sh` 是**按现状提供、不作任何保证**的便利
> 工具。它们已在常见的 RHEL/CentOS/Debian/Ubuntu 内核配置（开启
> `CONFIG_DYNAMIC_FTRACE=y` 和 `CONFIG_KALLSYMS_ALL=y`）上经过测试。在
> 生产环境部署前，请先在自有测试环境中验证。对于关键业务系统，推荐使用
> 手动内核重编译方案（方案 B）。

## 验证

```bash
# 1. 模块已加载
lsmod | grep hotfix

# 2. dmesg 中确认热补丁已生效
dmesg | grep "PATCH ACTIVE"

# 3. Sysfs 热补丁状态
cat /sys/kernel/livepatch/hotfix/enabled

# 4. kallsyms 中能看到已修补的符号
grep januscape /proc/kallsyms
```

## 故障排查

| 症状 | 可能原因 | 解决方法 |
|-----|---------|---------|
| `kvm_mmu_get_child_sp not in kallsyms` | 未设置 `CONFIG_KALLSYMS_ALL` | 检查内核配置 |
| `register_ftrace_direct: -22` | 函数未找到或已修补 | 验证 `grep kvm_mmu_get_child_sp /proc/kallsyms` |
| `insmod: Unknown symbol` | KVM 模块未加载 | 先执行 `modprobe kvm` |
| 加载后 dmesg 出现 `gfn mismatch` | 结构体偏移量错误 | 手动指定：`insmod hotfix.ko gfn_off=0x?? role_off=0x??` |
| 模块加载但热补丁未生效 | KVM 在热补丁之后加载 | 卸载热补丁，加载 KVM，再重新加载热补丁 |
| 找不到 `kernel-devel` | 缺少内核头文件 | 安装对应版本的 `kernel-devel-$(uname -r)` |

## 常见问题

### 需要重启吗？

**不需要。** 这是实时补丁。通过 `insmod` 加载，通过 `rmmod` 移除。不
影响任何正在运行的虚拟机。

### 会影响正在运行的虚拟机吗？

**不会。** 该修复只改变**未来** shadow MMU 遍历的 shadow page 复用
逻辑。现有的 shadow pages 不受影响。

### 低于 4.0 的内核怎么办？

不支持。4.0 之前的内核缺少 `FTRACE_OPS_FL_IPMODIFY`。如果仍在运行
RHEL 7（3.10），需要基于 `text_poke` 的方案（独立项目）或升级内核。

### arm64 受影响吗？

**不受。** Januscape（CVE-2026-53359）仅影响 x86。但 arm64 KVM 宿主机
应关注另一个独立漏洞 [ITScape (CVE-2026-46316)](https://github.com/V4bel/ITScape)。

### 如果我的内核已经包含上游修复怎么办？

安装器会检测到：
```bash
grep 'role.word' /proc/kallsyms && echo "已修补"
```

### 可以编译一次部署到多台机器吗？

可以。在安装了匹配 kernel-devel 的主机上编译：
```bash
cd kmod && make KDIR=/path/to/target-kernel-headers
# 将 hotfix.ko 分发到相同内核版本的主机
```

或使用 `make all-kernels` 为所有已安装的内核版本编译。

### QEMU 6.x 部分屏蔽了 PoC——我安全吗？

**不。** PoC 的嵌套 VMX 信号即使在 QEMU 6.x 上也**会到达宿主机 KVM**
（`dmesg` 中 `nested_vmx_load_cr3` 的调用栈轨迹已证实）。虚拟机崩溃
是因为 QEMU 6.x 的嵌套 VMX 模拟不完全，但逃逸信号已经越过了边界，
进入了存在漏洞的 KVM 路径。更精巧的触发序列可能无视 QEMU 版本赢得
竞争。请升级 QEMU **并**修补 KVM——不要将任何一方视为另一方的替代品。

## 项目结构

```
.
├── kmod/
│   ├── hotfix.c              # 通用内核模块（4.x–6.x）
│   ├── offsets_db.h          # 结构体偏移量数据库（降级方案）
│   └── Makefile              # 内核模块编译系统
├── installer/
│   ├── main.go               # Go 安装器（deploy/check/rollback/status）
│   └── go.mod                # Go 模块定义
├── apply.sh                  # Shell 部署脚本（替代方案）
├── .gitignore
├── README.md                 # 英文文档
└── README.zh-CN.md           # 中文文档（本文件）
```

## 许可证

GPL v2，详见 Linux 内核源码树中的 [COPYING](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/COPYING) 文件。

**版权所有 (c) 2026 AORIPUS (BEIJING) TECHNOLOGY CO., LTD. & GEELINX LTD.**
联系方式：master@aoripus.com

## 参考资料

- [原始 PoC — V4bel/Januscape](https://github.com/V4bel/Januscape)
- [上游修复 — commit 81ccda30b4e8](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=81ccda30b4e8)
- [lore.kernel.org 补丁讨论](https://lore.kernel.org/all/20260617134425.440091-1-pbonzini@redhat.com/)
- [oss-security 公告](https://www.openwall.com/lists/oss-security/2026/07/06/1)
- [Google kvmCTF](https://security.googleblog.com/2024/06/virtual-escape-real-reward-introducing.html)
