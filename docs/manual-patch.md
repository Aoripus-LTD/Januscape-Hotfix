# 手动内核补丁（内核重编译）

将上游修复永久内建于内核源码树，编译并安装新内核。
**需要重启宿主机，所有 VM 会停机。**

适用于：
- 有定期内核升级维护窗口的机房
- 希望将修复内建于发行版内核包中的场景
- 对热补丁方案有顾虑的环境

## 操作步骤

### 1. 下载上游修复

```bash
cd /path/to/linux-source
curl -L 'https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id=81ccda30b4e8' | patch -p1
```

### 2. 验证变更

```bash
git diff arch/x86/kvm/mmu/mmu.c
```

完整 diff（仅一个文件，10 行）：

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

### 3. 编译安装

按发行版流程：

```bash
# RHEL / CentOS
make rpm-pkg
rpm -ivh ~/rpmbuild/RPMS/x86_64/kernel-*.rpm

# Debian / Ubuntu
make bindeb-pkg
dpkg -i ../linux-*.deb

# Gentoo
make && make modules_install && make install

# Arch
makepkg -si
```

### 4. 重启切换新内核

```bash
grubby --set-default /boot/vmlinuz-<new-version>
reboot
```

## 合并日期

上游补丁 `81ccda30b4e8` 于 **2026-06-16** 合并入 Linux 主线。
在此日期之后编译的主线内核已包含修复，无需手动补丁。

## 如何检查当前内核是否已修复

```bash
grep 'role.word' /proc/kallsyms && echo "已修复" || echo "需要补丁"
```
