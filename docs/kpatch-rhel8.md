# kpatch 热修复 — RHEL 8.x / CentOS 8 / 魔方云（内核 4.18）

这些系统的 4.18 内核将 shadow page 分配函数命名为 `kvm_mmu_get_page`（6 参数），
而我们的 ftrace 模块替换目标是 `kvm_mmu_get_child_sp`（5 参数），
ABI 不兼容，ftrace 方案无法工作。

本方案改用 **kpatch** 框架，不在被调函数层级做替换，而是在 `FNAME(fetch)`
调用点**之前**校验 child shadow page。如果 gfn 或 role 不匹配，直接踢掉
旧映射让内核走正常分配路径——效果等价于上游 `81ccda30b4e8` 补丁，但规避了
函数签名差异。

## 前置条件

- RHEL 8.x / CentOS 8 / 魔方云系统（内核 4.18.0-xxx）
- `kpatch` 框架及编译环境
- 对应内核版本的 `kernel-debuginfo` 包

## 编译

### 1. 依赖检查

```bash
curl -sL https://code.yesongit.com/Akiame/Januscape-Hotfix/raw/branch/main/tools/kpatch-deps.sh | bash
```

脚本会自动检测并安装所有缺失依赖。

### 2. 手动安装（脚本不可用时）

```bash
# 基础工具链
dnf install -y gcc make git ccache kernel-devel-$(uname -r)

# kpatch 编译依赖
dnf install -y elfutils elfutils-devel elfutils-libelf-devel \
               pesign yum-utils openssl numactl-devel \
               bison flex openssl-devel rpm-build
```

### 3. 安装内核调试符号

```bash
# CentOS 官方 debuginfo 仓库（Stream 8）
dnf install -y dnf-plugins-core
dnf debuginfo-install -y kernel-$(uname -r)
```

如果 debuginfo 仓库不可用，手动配置后安装：

```bash
KVR=$(uname -r | sed 's/\.x86_64//')
dnf install -y kernel-debuginfo-${KVR}.x86_64 \
               kernel-debuginfo-common-x86_64-${KVR}.x86_64
```

> 不同发行版/镜像源的 debuginfo 仓库地址不同，以上为 CentOS Stream 8
> 官方默认路径。如果拉不到包，检查 `/etc/yum.repos.d/` 下 debuginfo
> repo 是否启用，或联系操作系统供应商获取调试符号包。

### 4. 安装 kpatch

```bash
git clone https://github.com/dynup/kpatch.git
cd kpatch && make && sudo make install
```

### 5. 编译热补丁

```bash
kpatch-build --skip-compiler-check cve-2026-53359-4.18-livepatch.patch
```

编译耗时约 10–20 分钟，取决于宿主机性能。如果中途报缺库错误，
重新运行 `tools/kpatch-deps.sh` 补充依赖后重试。

### 6. 加载

```bash
kpatch load kpatch-cve-2026-53359-*.ko
```

## 原理

修复不在 `kvm_mmu_get_child_sp` 内部，而是在 `FNAME(fetch)` 的 shadow
walk 循环中（`arch/x86/kvm/mmu/paging_tmpl.h`）。每次准备复用已有的
child shadow page 时，先校验它的 gfn 和 role 是否与当前请求匹配：

```c
if (is_shadow_present_pte(*it.sptep)) {
    child = to_shadow_page(*it.sptep & PT64_BASE_ADDR_MASK);
    if (unlikely(child->gfn != table_gfn ||
                 child->role.word != role.word)) {
        // 踢掉不匹配的旧映射，让 fetch 走正常分配路径
        drop_parent_pte(child, it.sptep);
        kvm_flush_remote_tlbs(vcpu->kvm);
    }
}
```

效果与上游 `81ccda30b4e8` 相同——阻止了 direct split page 被错误地
当作 indirect shadow page 复用。

## 致谢

`FNAME(fetch)` 调用点校验的思路来自社区安全研究者对 Januscape 漏洞
在 RHEL 8.x 4.18 内核上的适配工作。`kvm_mmu_get_page` 与
`kvm_mmu_get_child_sp` 的命名差异及 ABI 不兼容问题最早由
[@Huan-Starvm](https://code.yesongit.com) 在 issue #1 中提交并定位。
