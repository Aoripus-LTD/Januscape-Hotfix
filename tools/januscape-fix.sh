#!/bin/bash
# Januscape (CVE-2026-53359) — 全功能一键修复脚本
# 自动检测环境、推荐方案、多镜像自动 fallback

set -e

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; NC='\033[0m'
BOLD='\033[1m'

log()   { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }
title() { echo -e "\n${CYAN}${BOLD}$*${NC}"; }

GITHUB_BASE="https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"

MIRRORS=(
    "https://cdn.akaere.online/github.com/Aoripus-LTD/Januscape-Hotfix/raw/main"
    "https://ghproxy.net/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"
    "https://gh-proxy.org/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"
    "https://v4.gh-proxy.org/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"
    "https://v6.gh-proxy.org/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"
    "https://cdn.gh-proxy.org/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"
)

try_fetch() {
    local path="$1" tmp url
    tmp=$(mktemp)
    url="${GITHUB_BASE}/${path}"
    curl -sL --connect-timeout 3 -m 15 -o "$tmp" "$url" 2>/dev/null && \
        head -1 "$tmp" | grep -qE '^#!(/bin/bash|/bin/sh|/usr/bin/env)' && {
            cat "$tmp"; rm -f "$tmp"; return 0; }
    for url in "${MIRRORS[@]}"; do
        curl -sL --connect-timeout 3 -m 15 -o "$tmp" "${url}/${path}" 2>/dev/null && \
            head -1 "$tmp" | grep -qE '^#!(/bin/bash|/bin/sh|/usr/bin/env)' && {
                log "镜像: ${url%%/https*}" ; cat "$tmp"; rm -f "$tmp"; return 0; }
    done
    err "下载失败: $path (直连及所有镜像均不可用)"
    rm -f "$tmp"; return 1
}

run_audit()      { try_fetch tools/januscape-check.sh   | bash; }
run_logcheck()   { try_fetch tools/januscape-logcheck.sh | bash; }
run_kpatch_deps(){
    log "kpatch 编译环境准备"
    echo "  将安装: gcc make ccache elfutils pesign openssl 等编译依赖"
    echo "  以及内核调试符号包 (kernel-debuginfo)"
    echo ""
    local ans
    if [ -t 0 ]; then
        read -p "  开始安装? [y/N] " ans
    else
        read -p "  开始安装? [y/N] " ans </dev/tty
    fi
    if [ "$ans" != "y" ] && [ "$ans" != "Y" ]; then
        warn "已取消"; return
    fi

    # 先装基础依赖
    log "安装编译工具链..."
    dnf install -y gcc make ccache git wget elfutils elfutils-devel \
                   elfutils-libelf-devel pesign yum-utils openssl-devel \
                   rpm-build kernel-devel-$(uname -r) 2>&1 | tail -3

    # 调试符号包分发行版处理
    local KVR=$(uname -r | sed 's/\.x86_64//')
    log "安装 kernel-debuginfo..."
    if dnf install -y kernel-debuginfo-${KVR}.x86_64 \
                     kernel-debuginfo-common-x86_64-${KVR}.x86_64 2>/dev/null; then
        ok "debuginfo 安装完成"
    else
        warn "默认仓库无 debuginfo，尝试配置 CentOS Stream 8..."
        cat > /etc/yum.repos.d/centos-stream-8-debuginfo.repo << 'EOF'
[centos-stream-8-debuginfo]
name=CentOS Stream 8 Debuginfo
baseurl=http://vault.centos.org/centos/8-stream/Debuginfo/x86_64/os/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
        dnf clean metadata 2>/dev/null
        dnf install -y kernel-debuginfo-${KVR}.x86_64 \
                       kernel-debuginfo-common-x86_64-${KVR}.x86_64 2>&1 | tail -5 \
            || warn "debuginfo 仍安装失败，请手动安装后重试"
    fi

    # 编译 kpatch
    if command -v kpatch &>/dev/null; then
        ok "kpatch 已安装: $(kpatch --version 2>&1 | head -1)"
    else
        log "编译安装 kpatch..."
        local TMPD=$(mktemp -d)
        git clone https://github.com/dynup/kpatch.git "$TMPD/kpatch" 2>&1 | tail -1
        make -C "$TMPD/kpatch" -j$(nproc) 2>&1 | tail -3
        make -C "$TMPD/kpatch" install 2>&1 | tail -1
        rm -rf "$TMPD"
        ok "kpatch 安装完成"
    fi

    echo ""
    log "环境准备完成。下一步: kpatch-build --skip-compiler-check <patch-file>"
    echo "  详见: docs/kpatch-rhel8.md"
}

detect_region() {
    local c; c=$(curl -s --connect-timeout 3 -m 5 ipinfo.io 2>/dev/null | grep -oP '"country"\s*:\s*"\K[^"]+')
    [ -z "$c" ] && c=$(curl -s --connect-timeout 3 -m 5 https://api.myip.la/cn?json 2>/dev/null | grep -oP '"country_code"\s*:\s*"\K[^"]+')
    log "IP: ${c:-未知} | 下载自动 fallback 多镜像"
}
detect_env() {
    title "环境检测"

    KERNEL=$(uname -r)
    KARCH=$(uname -m)
    echo "  内核: $KERNEL ($KARCH)"

    # CPU 虚拟化类型
    if grep -q vmx /proc/cpuinfo 2>/dev/null; then
        VIRT_TYPE="Intel VMX"
        KVM_MOD="kvm_intel"
    elif grep -q svm /proc/cpuinfo 2>/dev/null; then
        VIRT_TYPE="AMD SVM"
        KVM_MOD="kvm_amd"
    else
        err "CPU 不支持硬件虚拟化"
        exit 1
    fi
    echo "  虚拟化: $VIRT_TYPE"

    # 嵌套虚拟化状态
    if [ -f "/sys/module/${KVM_MOD}/parameters/nested" ]; then
        NESTED=$(cat "/sys/module/${KVM_MOD}/parameters/nested")
        if [ "$NESTED" = "1" ] || [ "$NESTED" = "Y" ]; then
            warn "  嵌套虚拟化: 已开启 (攻击面存在)"
            NESTED_ON=1
        else
            ok "  嵌套虚拟化: 已关闭 (安全)"
            NESTED_ON=0
        fi
    else
        warn "  嵌套虚拟化: 模块未加载，无法判断"
        NESTED_ON=-1
    fi

    # 上游补丁状态
    if grep -q 'role.word' /proc/kallsyms 2>/dev/null; then
        ok "  上游补丁: 已安装"
        PATCHED=1
    else
        warn "  上游补丁: 未安装 (存在漏洞)"
        PATCHED=0
    fi

    # 运行中的 VM
    if command -v virsh &>/dev/null; then
        VMS=$(virsh list --name 2>/dev/null | grep -c . || echo 0)
    else
        VMS=$(ps aux | grep -c '[q]emu' 2>/dev/null || echo 0)
    fi
    echo "  运行中 VM: $VMS 台"

    # RHEL 8.x 特殊检测
    if grep -q 'kvm_mmu_get_page' /proc/kallsyms 2>/dev/null && \
       ! grep -q 'kvm_mmu_get_child_sp' /proc/kallsyms 2>/dev/null; then
        IS_RHEL8=1
        warn "  内核类型: RHEL 8.x 4.18 分支 (ftrace 热修复不可用)"
    else
        IS_RHEL8=0
    fi

    # 发行版
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "  发行版: $NAME"
    fi
}

# ── 方案推荐 ─────────────────────────────────────────────────────────
recommend() {
    title "方案推荐"

    if [ "$PATCHED" -eq 1 ]; then
        ok "内核已包含上游补丁，无需任何操作。"
        exit 0
    fi

    if [ "$NESTED_ON" -eq 0 ] || [ "$NESTED_ON" -eq -1 ]; then
        ok "嵌套虚拟化已关闭或未加载，攻击面不存在。"
        if [ "$PATCHED" -eq 0 ]; then
            warn "建议写入 modprobe.d 配置以确保持久化:"
            echo "  echo \"options $KVM_MOD nested=0\" > /etc/modprobe.d/disable-nested.conf"
        fi
        exit 0
    fi

    echo ""
    echo "  根据当前环境 (内核 $KERNEL, $VMS 台 VM 运行中):"
    echo ""

    if [ "$IS_RHEL8" -eq 1 ]; then
        echo "  ┌──────────┬──────┬──────┬────────────┬──────────┬────────────┬──────────┬────────────────────────────────┐"
        echo "  │ 方案     │ 复现 │ 难度 │ 宿主机重启 │ VM 重启  │ 生效时间   │ 长期有效 │ 影响                           │"
        echo "  ├──────────┼──────┼──────┼────────────┼──────────┼────────────┼──────────┼────────────────────────────────┤"
        echo "  │ nested=0 │ 高   │ 低   │ KVM 重载   │ √        │ 即时       │ ✓        │ 无法在 VM 内创建嵌套虚拟机     │"
        echo "  │ kpatch   │ 高   │ 中   │ ✕          │ ✕        │ 即时       │ ✓        │ 编译可能报错，需灵活调整依赖   │"
        echo "  │ 升级 7.1 │ 高   │ 中   │ √          │ √        │ 30分钟+重启│ ✓        │ 主线上游已含；魔方云修软链接   │"
        echo "  └──────────┴──────┴──────┴────────────┴──────────┴────────────┴──────────┴────────────────────────────────┘"
    elif [ "$VMS" -eq 0 ]; then
        echo "  ┌──────────┬──────┬──────┬────────────┬──────────┬────────────┬──────────┬────────────────────────────────┐"
        echo "  │ 方案     │ 复现 │ 难度 │ 宿主机重启 │ VM 重启  │ 生效时间   │ 长期有效 │ 影响                           │"
        echo "  ├──────────┼──────┼──────┼────────────┼──────────┼────────────┼──────────┼────────────────────────────────┤"
        echo "  │ nested=0 │ 高   │ 低   │ KVM 重载   │ √        │ 即时       │ ✓        │ 无法在 VM 内创建嵌套虚拟机     │"
        echo "  │ ftrace   │ 低   │ 高   │ ✕          │ ✕        │ 即时       │ ✓        │ 对内核版本精度要求高           │"
        echo "  │ 升级 7.1 │ 高   │ 中   │ √          │ √        │ 30分钟+重启│ ✓        │ 主线上游已含；魔方云修软链接   │"
        echo "  └──────────┴──────┴──────┴────────────┴──────────┴────────────┴──────────┴────────────────────────────────┘"
    else
        echo "  ┌──────────┬──────┬──────┬────────────┬──────────┬────────────┬──────────┬────────────────────────────────┐"
        echo "  │ 方案     │ 复现 │ 难度 │ 宿主机重启 │ VM 重启  │ 生效时间   │ 长期有效 │ 影响                           │"
        echo "  ├──────────┼──────┼──────┼────────────┼──────────┼────────────┼──────────┼────────────────────────────────┤"
        echo "  │ ftrace   │ 低   │ 高   │ ✕          │ ✕        │ 即时       │ ✓        │ 对内核版本精度要求高           │"
        echo "  │ nested=0 │ 高   │ 低   │ KVM 重载   │ √        │ 即时       │ ✓        │ 无法在 VM 内创建嵌套虚拟机     │"
        echo "  │ 升级 7.1 │ 高   │ 中   │ √          │ √        │ 30分钟+重启│ ✓        │ 主线上游已含；魔方云修软链接   │"
        echo "  └──────────┴──────┴──────┴────────────┴──────────┴────────────┴──────────┴────────────────────────────────┘"
    fi

    echo ""
    echo "  完整对比: https://github.com/Aoripus-LTD/Januscape-Hotfix"
}

# ── 菜单 ─────────────────────────────────────────────────────────────
show_menu() {
    echo ""
    echo "═════════════════════════════════════════════════════"
    echo "  Januscape (CVE-2026-53359) 修复工具箱"
    echo "  内核: $KERNEL | 虚拟化: $VIRT_TYPE | VM: ${VMS}台"
    echo "═════════════════════════════════════════════════════"
    echo ""
    echo "  方案对比:"
    echo "  ┌──────────┬──────┬──────┬────────────┬──────────┬────────────┬──────────┬────────────────────────────────┐"
    echo "  │ 方案     │ 复现 │ 难度 │ 宿主机重启 │ VM 重启  │ 生效时间   │ 长期有效 │ 影响                           │"
    echo "  ├──────────┼──────┼──────┼────────────┼──────────┼────────────┼──────────┼────────────────────────────────┤"
    echo "  │ nested=0 │ 高   │ 低   │ KVM 重载   │ √        │ 即时       │ ✓        │ 无法在 VM 内创建嵌套虚拟机     │"
    if [ "$IS_RHEL8" -eq 1 ]; then
        echo "  │ kpatch   │ 高   │ 中   │ ✕          │ ✕        │ 即时       │ ✓        │ 编译可能报错，需灵活调整依赖   │"
    else
        echo "  │ ftrace   │ 低   │ 高   │ ✕          │ ✕        │ 即时       │ ✓        │ 对内核版本精度要求高           │"
    fi
    echo "  │ 重编译   │ 高   │ 高   │ √          │ √        │ 编译+重启  │ ✓        │ 一次修改永久有效，不依赖补丁   │"
    echo "  │ 升级 7.1 │ 高   │ 中   │ √          │ √        │ 30分钟+重启│ ✓        │ 主线上游已含；魔方云修软链接   │"
    echo "  └──────────┴──────┴──────┴────────────┴──────────┴────────────┴──────────┴────────────────────────────────┘"
    echo ""
    echo "  ${BOLD}操作${NC}"
    echo "  1) 集群审计                2) 崩溃日志取证"
    echo "  3) nested=0 一键关闭      4) ftrace 编译加载"
    if [ "$IS_RHEL8" -eq 1 ]; then
        echo "  5) kpatch 环境准备 (依赖检查 & 安装)  6) 查看完整文档"
    else
        echo "  5) 查看完整文档"
    fi
    echo "  0) 退出"
    echo ""
    CHOICE_MAX=6
    [ "$IS_RHEL8" -eq 0 ] && CHOICE_MAX=5
    if [ -t 0 ]; then
        read -p "  请选择 [0-${CHOICE_MAX}]: " CHOICE
    else
        read -p "  请选择 [0-${CHOICE_MAX}]: " CHOICE </dev/tty
    fi

    case $CHOICE in
        1) run_audit ;;
        2) run_logcheck ;;
        3)
            if [ "$VMS" -gt 0 ]; then
                warn "当前有 ${VMS} 台 VM 正在运行！关闭嵌套虚拟化需要重载 KVM 模块，"
                warn "这会导致所有 VM 被强制关机。"
                echo ""
                local ans1 ans2
                if [ -t 0 ]; then
                    read -p "  确认关机全部 ${VMS} 台 VM? [y/N] " ans1
                else
                    read -p "  确认关机全部 ${VMS} 台 VM? [y/N] " ans1 </dev/tty
                fi
                if [ "$ans1" != "y" ] && [ "$ans1" != "Y" ]; then
                    warn "已取消"; return
                fi
                if [ -t 0 ]; then
                    read -p "  再次确认: 这将不可逆地关闭所有 VM，继续? [y/N] " ans2
                else
                    read -p "  再次确认: 这将不可逆地关闭所有 VM，继续? [y/N] " ans2 </dev/tty
                fi
                if [ "$ans2" != "y" ] && [ "$ans2" != "Y" ]; then
                    warn "已取消"; return
                fi
                log "正在关闭所有 VM..."
                virsh list --name 2>/dev/null | xargs -r -I{} virsh destroy {}
                sleep 3
            fi
            echo "options $KVM_MOD nested=0" > /etc/modprobe.d/disable-nested.conf
            ok "已写入 /etc/modprobe.d/disable-nested.conf (重启后永久生效)"
            rmmod $KVM_MOD 2>/dev/null && modprobe $KVM_MOD nested=0
            cat "/sys/module/${KVM_MOD}/parameters/nested"
            ;;
        4)
            log "下载并编译 ftrace 热修复模块..."
            TMPD=$(mktemp -d)
            try_fetch kmod/hotfix.c      > "$TMPD/hotfix.c"
            try_fetch kmod/offsets_db.h   > "$TMPD/offsets_db.h"
            try_fetch kmod/Makefile       > "$TMPD/Makefile"
            cd "$TMPD"
            if make KDIR="/lib/modules/$KERNEL/build" 2>&1 | tail -5; then
                insmod hotfix.ko
                dmesg | grep -E 'PATCH ACTIVE|januscape' | tail -5
            else
                err "编译失败，请检查 kernel-devel 是否安装"
            fi
            cd - >/dev/null; rm -rf "$TMPD"
            ;;
        5)
            if [ "$IS_RHEL8" -eq 1 ]; then
                run_kpatch_deps
            else
                show_docs
            fi
            ;;
        6) show_docs ;;
        0) exit 0 ;;
        *) warn "无效选择" ;;
    esac
}

show_docs() {
    echo "  完整文档: https://github.com/Aoripus-LTD/Januscape-Hotfix"
    echo ""
    echo "  各方案明细:"
    echo "  - nested=0:     docs/nested-disable.md"
    echo "  - ftrace 热修复: docs/ftrace-hotfix.md"
    echo "  - kpatch:       docs/kpatch-rhel8.md"
    echo "  - 内核重编译:   docs/manual-patch.md"
    echo "  - 内核升级 7.1: docs/kernel-upgrade.md"
}

# ── 主入口 ───────────────────────────────────────────────────────────
main() {
    echo ""
    echo "  ╔══════════════════════════════════════════╗"
    echo "  ║  Januscape (CVE-2026-53359) 修复工具箱   ║"
    echo "  ║  AORIPUS & GEELINX LTD.                 ║"
    echo "  ╚══════════════════════════════════════════╝"

    if [ "$(id -u)" -ne 0 ]; then
        err "需要 root 权限运行"
        exit 1
    fi

    detect_region
    detect_env
    recommend

    if [ -t 0 ]; then
        read -p "  进入交互菜单? [Y/n] " ANS
    else
        read -p "  进入交互菜单? [Y/n] " ANS </dev/tty
    fi
    if [ "$ANS" != "n" ] && [ "$ANS" != "N" ]; then
        while true; do
            show_menu
        done
    fi
}

main
