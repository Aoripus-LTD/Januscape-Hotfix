# kpatch 方案 — RHEL 8.x / CentOS 8（内核 4.18）

RHEL 8.x / CentOS 8 的 4.18 内核使用 `kvm_mmu_get_page`（6 参数 ABI），
而 ftrace hotfix 模块的替换目标是 `kvm_mmu_get_child_sp`（5 参数 ABI），
签名不兼容，无法安全替换。

本方案在 `FNAME(fetch)` 的**调用点**做 child shadow page 校验，而非替换
被调函数，避开了 ABI 不兼容问题。

## 前置条件

- RHEL 8.x / CentOS 8（内核版本 4.18.0-xxx）
- 安装了 `kpatch` 及相关依赖
- 安装了对应内核版本的 `kernel-debuginfo`

## 编译部署

### 1. 安装依赖

```bash
dnf install gcc kernel-devel elfutils elfutils-devel ccache
dnf install pesign yum-utils openssl wget numactl-devel
dnf install elfutils-libelf-devel bison flex openssl-devel
dnf install rpm-build
yum-builddep kernel
```

### 2. 安装内核调试符号

```bash
cat > /etc/yum.repos.d/centos-stream-8-debuginfo.repo << 'EOF'
[centos-stream-8-debuginfo]
name=CentOS Stream 8 Debuginfo
baseurl=https://mirrors.zggb.com/centos-debuginfo/8-stream/x86_64/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF

dnf clean metadata
dnf makecache --enablerepo=centos-stream-8-debuginfo
KVR=$(uname -r | sed 's/\.x86_64//')
dnf install -y --enablerepo=centos-stream-8-debuginfo \
  kernel-debuginfo-${KVR}.x86_64 \
  kernel-debuginfo-common-x86_64-${KVR}.x86_64
```

### 3. 编译 kpatch

```bash
git clone https://github.com/dynup/kpatch.git
cd kpatch && make && sudo make install
```

### 4. 编译热补丁

```bash
kpatch-build --skip-compiler-check cve-2026-53359-4.18-livepatch.patch
# 编译约需 15 分钟。
# 如中途报错，用 cat 查看日志，缺失什么库就补装什么。
```

### 5. 加载

```bash
kpatch load kpatch-cve-2026-53359-*.ko
```

## 补丁原理

补丁位置在 `arch/x86/kvm/mmu/paging_tmpl.h` 的 `FNAME(fetch)` 中。
在复用已有 shadow page 之前，先校验其 gfn 和 role，不匹配则踢掉：

```c
if (is_shadow_present_pte(*it.sptep)) {
    child = to_shadow_page(*it.sptep & PT64_BASE_ADDR_MASK);
    if (unlikely(child->gfn != table_gfn ||
                 child->role.word != role.word)) {
        drop_parent_pte(child, it.sptep);
        kvm_flush_remote_tlbs(vcpu->kvm);
    }
}
```

这样即使 `kvm_mmu_get_page()` 的 gfn-only 复用逻辑有问题，fetch 层也会在
复用发生前拦截并修正。

## 致谢

本方案基于社区贡献的 `cve-2026-53359-rhel418-livepatch-v2.patch`，
在 `FNAME(fetch)` 调用点做校验的思路避免了 RHEL 8.x 内核上
`kvm_mmu_get_page` 与 `kvm_mmu_get_child_sp` 的 ABI 不兼容问题。
感谢社区安全研究者对 Januscape 漏洞的持续关注和代码贡献。
