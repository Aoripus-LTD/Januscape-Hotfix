# 内核升级 — Linux 7.1.3 源码编译

适用于 CentOS Stream 8 / RHEL 8 / 魔方云系统。通过升级到 Linux Kernel 7.1.3
完整修复 CVE-2026-53359。此版本主线已包含上游补丁 `81ccda30b4e8`。

相较于内核重编译旧版本，直接升级到较新主线的好处：
- 补丁已内置，无需手动打 patch
- KVM shadow MMU 相关代码经过多个版本的稳定性改进
- 可以作为后续长期跟随的主线基准版本

## 前置条件

- CentOS Stream 8 x86_64
- 魔方云系统（需额外修复 Python 软链接，见下文）
- 磁盘可用空间 ≥ 30 GB（源码 + 编译产物）
- 内存 ≥ 4 GB（建议 8 GB 以上，-j$(nproc) 并行编译）
- 编译耗时约 30–60 分钟

## 编译安装

### 1. 安装编译依赖

```bash
dnf groupinstall -y "Development Tools"
dnf install -y ncurses-devel openssl-devel elfutils-libelf-devel \
               bison flex bc perl perl-devel
```

### 2. 下载内核源码

```bash
cd /usr/src
wget https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.3.tar.xz
tar xf linux-7.1.3.tar.xz
cd linux-7.1.3
```

### 3. 配置内核

```bash
# 以当前运行内核的配置为基准
zcat /proc/config.gz > .config 2>/dev/null || \
  cp /boot/config-$(uname -r) .config

# 合并新版本新增选项（全部默认）
make olddefconfig

# 关闭模块签名 (发行版内核配置默认开启但无有效 key，会导致 modules_install 失败)
scripts/config --disable MODULE_SIG --disable MODULE_SIG_FORCE
make olddefconfig

# 确认 KVM 相关选项
grep -E 'CONFIG_KVM=|CONFIG_KVM_INTEL|CONFIG_KVM_AMD|CONFIG_KALLSYMS_ALL' .config
```

### 4. 编译

```bash
make -j$(nproc)
make modules_install
make install
```

### 5. 设置默认启动项 & 重启

```bash
grubby --set-default /boot/vmlinuz-7.1.3
reboot
```

## 重启后验证

```bash
uname -r                  # → 7.1.3
lsmod | grep kvm          # KVM 模块正常加载
grep 'role.word' /proc/kallsyms && echo "已修复"
```

## 回滚

如果新内核启动异常，GRUB 菜单选择旧内核启动后：

```bash
grubby --set-default /boot/vmlinuz-4.18.0-xxx.el8.x86_64
```

## 魔方云用户必做

重启后执行：

```bash
ln -s /usr/bin/python3 /usr/bin/python
```

部分魔方云面板组件依赖 `/usr/bin/python` 路径，7.1 主线移除了 Python 2，
只保留 `python3`，需手动创建软链接。

## 常见错误

### `sign-file: error: no start line` — 模块签名失败

编译到 `make modules_install` 阶段报错：

```
SSL error:0909006c:PEM routines:get_name:no start line
sign-file:./
make[2]: *** [scripts/Makefile.modinst:125] Error
```

原因：发行版内核的 `.config` 默认开启了 `CONFIG_MODULE_SIG`，但没有
有效的模块签名密钥。执行 `make olddefconfig` 之前需关闭：

```bash
scripts/config --disable MODULE_SIG --disable MODULE_SIG_FORCE
make olddefconfig
```

然后重新 `make -j$(nproc)` 和 `make modules_install`。

## 脚本化（批量部署）

可以将上述步骤封装为脚本在多台宿主机上执行。编译阶段使用 `nohup` 后台运行，
避免 SSH 断开中断：

```bash
nohup bash kernel-upgrade.sh > /root/kernel-upgrade.log 2>&1 &
tail -f /root/kernel-upgrade.log
```

脚本支持断点续跑——重复执行时已下载的源码和已完成的编译步骤会自动跳过。
