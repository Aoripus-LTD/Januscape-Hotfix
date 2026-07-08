#!/bin/bash
# Januscape (CVE-2026-53359) — 全功能一键修复脚本
# 自动检测环境、推荐方案、支持中国大陆 GitHub 镜像加速

set -e

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; NC='\033[0m'
BOLD='\033[1m'

log()   { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }
title() { echo -e "\n${CYAN}${BOLD}$*${NC}"; }

GITHUB_BASE="https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"

# ── IP 定位：判断是否在中国大陆 ──────────────────────────────────────
detect_region() {
    local country
    country=$(curl -s --connect-timeout 3 -m 5 ipinfo.io 2>/dev/null | \
              grep -oP '"country"\s*:\s*"\K[^"]+')

    # ipinfo.io 被墙时 fallback
    if [ -z "$country" ]; then
        country=$(curl -s --connect-timeout 3 -m 5 https://api.myip.la/cn?json 2>/dev/null | \
                  grep -oP '"country_code"\s*:\s*"\K[^"]+')
    fi

    if [ "$country" = "CN" ]; then
        echo ""
        # 管道执行时 stdin 不是终端，用 /dev/tty 接管交互
        if [ -t 0 ]; then
            read -p "  检测到中国大陆 IP，是否使用 GitHub 镜像加速? [Y/n] " ANS
        else
            read -p "  检测到中国大陆 IP，是否使用 GitHub 镜像加速? [Y/n] " ANS </dev/tty
        fi
        if [ "$ANS" != "n" ] && [ "$ANS" != "N" ]; then
            GITHUB_BASE="https://cdn.akaere.online/github.com/Aoripus-LTD/Januscape-Hotfix/raw/main"
            log "已切换 GitHub 镜像"
        else
            log "使用 GitHub 直连"
        fi
    else
        log "IP 归属: ${country:-未知}，使用 GitHub 直连"
    fi
}

# GitHub 资源下载（自动适配镜像）
gh_raw() {
    curl -sL --connect-timeout 5 -m 300 "${GITHUB_BASE}/$1"
}

# ── 环境检测 ─────────────────────────────────────────────────────────
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
        echo -e "  ${BOLD}推荐方案:${NC}"
        echo "    1. nested=0          — 最简 (如可接受关闭嵌套)"
        echo "    2. kpatch            — 在线修复 (RHEL 8.x 专用)"
        echo "    3. 内核升级 7.1       — 永久修复"
    elif [ "$VMS" -eq 0 ]; then
        echo -e "  ${BOLD}推荐方案:${NC}"
        echo "    1. nested=0          — 最简 (无 VM, 直接关嵌套)"
        echo "    2. ftrace 热修复     — 在线修复"
        echo "    3. 内核升级 7.1       — 永久修复"
    else
        echo -e "  ${BOLD}推荐方案:${NC}"
        echo "    1. ftrace 热修复     — ${VMS}台 VM 在线修复, 不停机"
        echo "    2. nested=0          — 需停 VM 重载 KVM"
        echo "    3. 内核升级 7.1       — 需全部停机重启"
    fi

    echo ""
    echo "  完整对比: https://github.com/Aoripus-LTD/Januscape-Hotfix"
}

# ── 在线执行子脚本 ───────────────────────────────────────────────────
run_audit()    { gh_raw tools/januscape-check.sh    | bash; }
run_logcheck() { gh_raw tools/januscape-logcheck.sh  | bash; }
run_kpatch_deps() { gh_raw tools/kpatch-deps.sh | bash; }

# ── 菜单 ─────────────────────────────────────────────────────────────
show_menu() {
    echo ""
    echo "═══════════════════════════════════════════"
    echo "  Januscape (CVE-2026-53359) 修复工具箱"
    echo "  内核: $KERNEL | 虚拟化: $VIRT_TYPE"
    echo "═══════════════════════════════════════════"
    echo ""
    echo -e "  ${BOLD}排查${NC}"
    echo "  1) 集群审计            (januscape-check.sh)"
    echo "  2) 崩溃日志取证        (januscape-logcheck.sh)"
    echo ""
    echo -e "  ${BOLD}修复${NC}"
    echo "  3) nested=0 一键关闭嵌套"
    echo "  4) ftrace 热修复        (编译 & 加载)"
    echo "  5) kpatch 依赖检查      (RHEL 8.x 专用)"
    echo "  6) 查看完整文档"
    echo ""
    echo "  0) 退出"
    echo ""
    if [ -t 0 ]; then
        read -p "  请选择 [0-6]: " CHOICE
    else
        read -p "  请选择 [0-6]: " CHOICE </dev/tty
    fi

    case $CHOICE in
        1) run_audit ;;
        2) run_logcheck ;;
        3)
            echo "options $KVM_MOD nested=0" > /etc/modprobe.d/disable-nested.conf
            ok "已写入 /etc/modprobe.d/disable-nested.conf"
            if [ "$VMS" -eq 0 ]; then
                log "无 VM 运行，立即重载 KVM..."
                rmmod $KVM_MOD 2>/dev/null && modprobe $KVM_MOD nested=0
                cat "/sys/module/${KVM_MOD}/parameters/nested"
            else
                warn "$VMS 台 VM 在运行，请先关闭或等待下次重启生效"
            fi
            ;;
        4)
            log "下载并编译 ftrace 热修复模块..."
            TMPD=$(mktemp -d)
            gh_raw kmod/hotfix.c      > "$TMPD/hotfix.c"
            gh_raw kmod/offsets_db.h   > "$TMPD/offsets_db.h"
            gh_raw kmod/Makefile       > "$TMPD/Makefile"

            cd "$TMPD"
            if make KDIR="/lib/modules/$KERNEL/build" 2>&1 | tail -5; then
                insmod hotfix.ko
                dmesg | grep -E 'PATCH ACTIVE|januscape' | tail -5
            else
                err "编译失败，请检查 kernel-devel 是否安装"
            fi
            cd - >/dev/null
            rm -rf "$TMPD"
            ;;
        5) run_kpatch_deps ;;
        6)
            echo "  完整文档: https://github.com/Aoripus-LTD/Januscape-Hotfix"
            echo ""
            echo "  方案对比:"
            echo "  - nested=0:     docs/nested-disable.md"
            echo "  - ftrace 热修复: docs/ftrace-hotfix.md"
            echo "  - kpatch:       docs/kpatch-rhel8.md"
            echo "  - 内核重编译:   docs/manual-patch.md"
            echo "  - 内核升级 7.1: docs/kernel-upgrade.md"
            ;;
        0) exit 0 ;;
        *) warn "无效选择" ;;
    esac
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
