#!/bin/bash
# kpatch 编译环境依赖检查与安装
# 适用: RHEL 8.x / CentOS 8 / 魔方云系统 (内核 4.18)

set -e

echo "=== kpatch 编译环境检查 ==="
echo "目标内核: $(uname -r)"
echo

MISSING=""

check_cmd() {
    if ! command -v "$1" &>/dev/null; then
        echo "  ❌ $1"
        MISSING="$MISSING $2"
    else
        echo "  ✅ $1"
    fi
}

check_pkg() {
    if ! rpm -q "$1" &>/dev/null; then
        echo "  ❌ $1 (rpm)"
        MISSING="$MISSING $1"
    else
        echo "  ✅ $1"
    fi
}

check_devel() {
    local pkg="$1"
    local path="$2"
    if [ -f "$path" ]; then
        echo "  ✅ $pkg"
    else
        echo "  ❌ $pkg"
        MISSING="$MISSING $pkg"
    fi
}

echo "--- 基础编译工具 ---"
check_cmd gcc      gcc
check_cmd make      make
check_cmd git       git
check_cmd wget      wget
check_cmd ccache    ccache

echo
echo "--- kpatch 编译依赖 (rpm) ---"
for pkg in elfutils elfutils-devel elfutils-libelf-devel \
           pesign yum-utils openssl numactl-devel \
           bison flex openssl-devel rpm-build; do
    check_pkg "$pkg"
done

echo
echo "--- 内核开发包 ---"
check_devel "kernel-devel" "/lib/modules/$(uname -r)/build/Makefile"
check_devel "kernel-debuginfo" "/usr/lib/debug/lib/modules/$(uname -r)/vmlinux"

echo
echo "--- kpatch ---"
if command -v kpatch &>/dev/null; then
    echo "  ✅ kpatch ($(kpatch --version 2>&1 | head -1))"
elif [ -f /usr/local/bin/kpatch ]; then
    echo "  ✅ kpatch (/usr/local/bin/kpatch)"
else
    echo "  ❌ kpatch (需要编译安装)"
fi

echo

if [ -z "$MISSING" ]; then
    echo "=== 所有依赖已就绪，可以开始编译 ==="
    exit 0
fi

echo "=== 缺失依赖: $MISSING ==="
echo
read -p "是否自动安装缺失的依赖? [y/N] " ANS

if [ "$ANS" != "y" ] && [ "$ANS" != "Y" ]; then
    echo "手动安装: dnf install -y $MISSING"
    exit 1
fi

# 安装基础依赖
echo "$MISSING" | grep -qE 'gcc|make|git|wget|ccache' && {
    dnf install -y gcc make git wget ccache
}

# 安装 kpatch 编译依赖
dnf install -y elfutils elfutils-devel elfutils-libelf-devel \
               pesign yum-utils openssl numactl-devel \
               bison flex openssl-devel rpm-build

# 安装 kernel-devel
if echo "$MISSING" | grep -q "kernel-devel"; then
    dnf install -y "kernel-devel-$(uname -r)"
fi

# 安装 kernel-debuginfo
if echo "$MISSING" | grep -q "kernel-debuginfo"; then
    KVR=$(uname -r | sed 's/\.x86_64//')
    dnf install -y --enablerepo=centos-stream-8-debuginfo \
        "kernel-debuginfo-${KVR}.x86_64" \
        "kernel-debuginfo-common-x86_64-${KVR}.x86_64"
fi

# 编译安装 kpatch
if echo "$MISSING" | grep -q "kpatch"; then
    echo "正在编译 kpatch..."
    TMPD=$(mktemp -d)
    git clone https://github.com/dynup/kpatch.git "$TMPD/kpatch"
    make -C "$TMPD/kpatch" -j$(nproc)
    make -C "$TMPD/kpatch" install
    rm -rf "$TMPD"
    echo "kpatch 安装完成"
fi

echo
echo "=== 依赖安装完成，请重新运行本脚本验证 ==="
