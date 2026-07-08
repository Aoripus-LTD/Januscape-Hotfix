#!/bin/bash
# Januscape (CVE-2026-53359) — 全功能一键修复脚本
# ⚠️  本脚本未经过充分测试，仅供参考。优先建议按文档手动操作。
# 完整文档: https://github.com/Aoripus-LTD/Januscape-Hotfix
# 各方案独立文档: docs/

VERSION="v26.7.8-beta83"

set -e

RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; NC='\033[0m'
BOLD='\033[1m'

log()   { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
err()   { echo -e "${RED}[✗]${NC} $*"; }
title() { echo -e "\n${CYAN}${BOLD}$*${NC}"; }

GITHUB_BASE="https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main"

# ── 版本校验：本地 vs 远程 ─────────────────────────────────────────
check_version() {
    local remote_ver
    remote_ver=$(curl -sL --connect-timeout 3 -m 5 \
        "https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/tools/januscape-fix.sh" 2>/dev/null | \
        grep '^VERSION=' | head -1 | cut -d'"' -f2)
    if [ -n "$remote_ver" ] && [ "$remote_ver" != "$VERSION" ]; then
        warn "当前版本: $VERSION — 最新版本: $remote_ver"
        warn "你运行的可能是旧版缓存，建议重新下载:"
        echo "  curl -sL https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/tools/januscape-fix.sh | sudo bash"
    else
        log "脚本版本: $VERSION (最新)"
    fi
}

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

    # 前置: 内核版本预检 + 预编译 .ko 匹配
    local KVER=$(uname -r | grep -oP '4\.18\.0-\K[0-9]+')
    local KO_FILE="cve202653359-rhel4.18.0-${KVER}.ko"
    local KO_URL="https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/installer/${KO_FILE}"

    case "$KVER" in
        408|496|500|553)
            ok "内核 ${KVER} 匹配预编译补丁"

            # 尝试直接下载预编译 .ko (GitHub → 自建 CDN fallback)
            local LOADED=0
            for KO_URL in \
                "https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/installer/${KO_FILE}" \
                "https://ghproxy.net/https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/installer/${KO_FILE}" \
                "https://www.aoripus.cn/dl/${KO_FILE}"; do
                log "下载预编译补丁: ${KO_URL##*/}"
                curl -#L --connect-timeout 10 -m 120 -o "/tmp/${KO_FILE}" "$KO_URL" 2>/dev/null
                if [ -s "/tmp/${KO_FILE}" ]; then
                    kpatch load "/tmp/${KO_FILE}" 2>/dev/null && LOADED=1 && break
                    rm -f "/tmp/${KO_FILE}"
                fi
            done

            if [ "$LOADED" -eq 1 ]; then
                ok "预编译补丁已加载"
                rm -f "/tmp/${KO_FILE}"
                echo ""
                local ans
                if [ -t 0 ]; then
                    read -p "  是否运行环境检测验证补丁状态? [Y/n] " ans
                else
                    read -p "  是否运行环境检测验证补丁状态? [Y/n] " ans </dev/tty
                fi
                [ "$ans" != "n" ] && [ "$ans" != "N" ] && detect_env
                return
            fi
            warn "预编译包下载失败，切换在线编译模式..."
            rm -f "/tmp/${KO_FILE}"
            ;;
        552)
            err "内核 552 代码结构不兼容 — kpatch 无法编译"
            echo "  552 的 paging_tmpl.h 已重构，patch 上下文不匹配"
            echo ""
            echo "  替代方案:"
            echo "    1. nested=0 关闭嵌套虚拟化 (无需编译)"
            echo "    2. 内核升级 7.1  (源码编译，自带补丁)"
            return ;;
        *)
            warn "内核 ${KVER} 未经测试 — 可能不兼容"
            warn "已验证子版本: 408, 496, 500, 553"
            local ans0
            if [ -t 0 ]; then
                read -p "  是否继续在线编译? [y/N] " ans0
            else
                read -p "  是否继续在线编译? [y/N] " ans0 </dev/tty
            fi
            [ "$ans0" != "y" ] && [ "$ans0" != "Y" ] && return ;;
    esac

    # 前置检查: kernel-devel — 没有就尝试安装
    if [ ! -f "/lib/modules/$(uname -r)/build/Makefile" ]; then
        warn "kernel-devel 未安装，尝试从仓库获取..."
        # 先试默认仓库
        if ! dnf install -y kernel-devel-$(uname -r) 2>/dev/null | grep -q '已安装\|Complete'; then
            # 再试发行版仓库 (main → vault 降级)
            local DID=""
            [ -f /etc/os-release ] && DID=$(grep -oP '^ID="?\K[^"]+' /etc/os-release)
            grep -qi rocky /etc/os-release 2>/dev/null && DID="rocky"
            grep -qi alma  /etc/os-release 2>/dev/null && DID="alma"
            local VER=$(grep -oP '^VERSION_ID="?\K[0-9.]+' /etc/os-release 2>/dev/null)
            local MAJOR="${VER%%.*}"

            # Rocky/Alma 用 pub (活跃版本) → vault (EOL 版本) 降级
            local PUB_BASE="" VAULT_BASE=""
            case "$DID" in
                rocky) PUB_BASE="https://dl.rockylinux.org/pub/rocky/${VER}"
                       VAULT_BASE="https://dl.rockylinux.org/vault/rocky/${VER}" ;;
                alma)  PUB_BASE="https://repo.almalinux.org/almalinux/${VER}"
                       VAULT_BASE="https://repo.almalinux.org/vault/${VER}" ;;
                *)     VAULT_BASE="https://mirrors.aliyun.com/centos-vault/8-stream" ;;
            esac

            for BASE in "$PUB_BASE" "$VAULT_BASE"; do
                [ -z "$BASE" ] && continue
                warn "尝试 ${DID}: ${BASE}..."
                cat > /etc/yum.repos.d/el8-temp.repo << EOF
[el8-temp-baseos]
name=EL8 Temporary BaseOS
baseurl=${BASE}/BaseOS/x86_64/os/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
                dnf clean metadata 2>/dev/null
                dnf install -y kernel-devel-$(uname -r) 2>/dev/null | tail -3
                [ -f "/lib/modules/$(uname -r)/build/Makefile" ] && break
            done

            # 如果本发行版找不到，尝试所有已知 RHEL 8 系源
            if [ ! -f "/lib/modules/$(uname -r)/build/Makefile" ]; then
                warn "本发行版仓库无此内核，尝试 Rocky / Alma vault..."
                local ALL_VAULTS=(
                    "https://dl.rockylinux.org/pub/rocky/8.10"
                    "https://dl.rockylinux.org/vault/rocky/8.9"
                    "https://dl.rockylinux.org/vault/rocky/8.8"
                    "https://dl.rockylinux.org/vault/rocky/8.7"
                    "https://dl.rockylinux.org/vault/rocky/8.6"
                    "https://repo.almalinux.org/almalinux/8.10"
                    "https://repo.almalinux.org/vault/8.9"
                    "https://repo.almalinux.org/vault/8.8"
                )
                for VAULT in "${ALL_VAULTS[@]}"; do
                    cat > /etc/yum.repos.d/el8-temp.repo << EOF
[el8-temp-baseos]
name=EL8 External Vault BaseOS
baseurl=${VAULT}/BaseOS/x86_64/os/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
                    dnf clean metadata 2>/dev/null
                    dnf install -y kernel-devel-$(uname -r) 2>/dev/null | tail -3
                    [ -f "/lib/modules/$(uname -r)/build/Makefile" ] && break
                done
            fi
        fi
    fi

    if [ ! -f "/lib/modules/$(uname -r)/build/Makefile" ]; then
        err "kernel-devel 安装失败 — 内核 $(uname -r) 无可用开发包"
        warn "此内核已从所有仓库移除 (EOL)，kpatch 无法编译。"
        echo ""
        echo "  替代方案:"
        echo "    1. nested=0 关闭嵌套虚拟化 (无需编译)"
        echo "    2. 内核升级 7.1  (源码编译，自带补丁)"
        rm -f /etc/yum.repos.d/el8-temp-*.repo
        return
    fi
    ok "kernel-devel 可用"

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

    log "安装编译工具链..."
    dnf install -y gcc make ccache git wget elfutils elfutils-devel \
                   elfutils-libelf-devel pesign yum-utils openssl-devel \
                   rpm-build 2>/dev/null | tail -3
    ok "编译工具链已就绪"

    # 调试符号: 直接搜已知存在路径的包
    local KVR=$(uname -r | sed 's/\.x86_64//') DEBUGINFO_OK=0
    log "安装 kernel-debuginfo..."

    # 方法 1: dnf debuginfo-install (标准 RHEL 系做法)
    if dnf debuginfo-install -y kernel-$(uname -r) 2>/dev/null; then
        # dnf 返回 0 不代表装上了，要真检查文件
        [ -f "/usr/lib/debug/lib/modules/$(uname -r)/vmlinux" ] && DEBUGINFO_OK=1
    fi

    # 方法 2: 配置 CentOS debuginfo 仓库后用 dnf 装
    if [ "$DEBUGINFO_OK" -eq 0 ]; then
        warn "debuginfo-install 失败，配置 CentOS debuginfo 仓库重试..."
        cat > /etc/yum.repos.d/centos-debuginfo.repo << 'EOF'
[centos-debuginfo]
name=CentOS 8 Stream Debuginfo
baseurl=http://debuginfo.centos.org/8-stream/x86_64/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
        dnf clean metadata 2>/dev/null
        if dnf install -y kernel-debuginfo-$(uname -r | sed 's/\.x86_64//').x86_64 \
                         kernel-debuginfo-common-x86_64-$(uname -r | sed 's/\.x86_64//').x86_64 2>&1 | tail -5; then
            [ -f "/usr/lib/debug/lib/modules/$(uname -r)/vmlinux" ] && DEBUGINFO_OK=1
        fi
        rm -f /etc/yum.repos.d/centos-debuginfo.repo
    fi

    # 方法 3: Rocky devel 仓库
    if [ "$DEBUGINFO_OK" -eq 0 ]; then
        warn "尝试 Rocky devel 仓库..."
        cat > /etc/yum.repos.d/rocky-devel.repo << 'EOF'
[rocky-devel]
name=Rocky 8 Devel
baseurl=https://dl.rockylinux.org/pub/rocky/8.10/devel/x86_64/os/
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
        dnf clean metadata 2>/dev/null
        if dnf install -y kernel-debuginfo-$(uname -r | sed 's/\.x86_64//').x86_64 \
                         kernel-debuginfo-common-x86_64-$(uname -r | sed 's/\.x86_64//').x86_64 2>&1 | tail -5; then
            [ -f "/usr/lib/debug/lib/modules/$(uname -r)/vmlinux" ] && DEBUGINFO_OK=1
        fi
        rm -f /etc/yum.repos.d/rocky-devel.repo
    fi

    if [ "$DEBUGINFO_OK" -eq 0 ]; then
        err "debuginfo 安装失败 — 内核 $(uname -r) 无可用调试符号包"
        warn "kpatch 无法在此内核上编译。"
        echo ""
        echo "  替代方案:"
        echo "    1. nested=0 关闭嵌套虚拟化 (无需编译)"
        echo "    2. 内核升级 7.1   (源码编译，自带补丁)"
        rm -f /etc/yum.repos.d/el8-temp-*.repo
        return
    fi
        ok "debuginfo 已确认安装"
    rm -f /etc/yum.repos.d/el8-temp-*.repo

    if command -v kpatch &>/dev/null; then
        ok "kpatch 已安装: $(kpatch --version 2>&1 | head -1)"
    else
        log "编译安装 kpatch..."
        local TMPD=$(mktemp -d)
        git clone https://github.com/dynup/kpatch.git "$TMPD/kpatch" 2>&1 | tail -1
        make -C "$TMPD/kpatch" -j$(nproc) 2>&1 | tail -3
        make -C "$TMPD/kpatch" install 2>&1 | tail -1
        rm -rf "$TMPD"
        # kpatch-build 有时装到 /usr/local/sbin
        export PATH="/usr/local/sbin:/usr/local/bin:$PATH"
        if command -v kpatch-build &>/dev/null; then
            ok "kpatch 安装完成 ($(which kpatch-build))"
        else
            warn "kpatch 编译完成但 kpatch-build 未找到"
            warn "请手动确认: ls /usr/local/sbin/kpatch-build"
        fi
    fi

    echo ""
    log "环境准备完成。"

    # 询问是否直接开始打补丁
    echo ""
    local ans3
    if [ -t 0 ]; then
        read -p "  是否立即开始 kpatch-build 编译补丁? [y/N] " ans3
    else
        read -p "  是否立即开始 kpatch-build 编译补丁? [y/N] " ans3 </dev/tty
    fi
    if [ "$ans3" = "y" ] || [ "$ans3" = "Y" ]; then
        local PATCHDIR=$(mktemp -d)
        log "下载补丁文件..."
        local PATCH_URL="https://raw.githubusercontent.com/Aoripus-LTD/Januscape-Hotfix/main/docs/cve-2026-53359-rhel418-livepatch.patch"
        curl -sL --connect-timeout 5 -m 30 -o "$PATCHDIR/fix.patch" "$PATCH_URL" 2>/dev/null
        if [ -f "$PATCHDIR/fix.patch" ] && grep -q 'kvm_mmu_page' "$PATCHDIR/fix.patch" 2>/dev/null; then
            cd "$PATCHDIR"
            # 自适应行号修正: 扫描内核源码找到 hunk 上下文起始行
            local SRC_FILE=$(find /root/.kpatch/src/ -name paging_tmpl.h 2>/dev/null | head -1)
            local NEW_LINE=""
            if [ -f "$SRC_FILE" ]; then
                NEW_LINE=$(grep -n 'shadow_walk_okay.*shadow_walk_next' "$SRC_FILE" | head -1 | cut -d: -f1)
                if [ -n "$NEW_LINE" ] && [ "$NEW_LINE" != "672" ]; then
                    local OLD_LINE=672
                    sed -i "s/@@ -${OLD_LINE},12 +${OLD_LINE},/@@ -${NEW_LINE},12 +${NEW_LINE},/" fix.patch
                    log "自适应行号: ${OLD_LINE} → ${NEW_LINE}"
                fi
            fi

            # 备份并全局替换 repo 中已失效的 vault.centos.org → Rocky vault
            local REPO_BAK=$(mktemp -d)
            cp /etc/yum.repos.d/*.repo "$REPO_BAK/" 2>/dev/null
            sed -i 's|vault\.centos\.org/centos-vault|dl.rockylinux.org/vault/centos|g' \
                /etc/yum.repos.d/*.repo 2>/dev/null

            log "开始 kpatch-build (预计 10-20 分钟)..."
            kpatch-build --skip-compiler-check fix.patch 2>&1 | tail -10 || true

            # 分析 build.log 给出诊断
            local BLOG="/root/.kpatch/build.log"
            if [ -f "$BLOG" ]; then
                if grep -q 'Hunk.*FAILED' "$BLOG" 2>/dev/null; then
                    warn "补丁行号不匹配 — 内核子版本 ${KERNEL} 不在本补丁支持范围"
                    warn "已测试的子版本: 408, 496, 500, 553"
                    echo "  替代方案: nested=0 或 内核升级 7.1"
                elif grep -q 'unexpected end of file' "$BLOG" 2>/dev/null; then
                    warn "补丁文件格式错误 — 请重新下载最新版本"
                elif grep -q 'kernel.*source\|Downloading kernel' "$BLOG" 2>/dev/null | grep -q 'ERROR\|Failed' 2>/dev/null; then
                    warn "内核源码下载失败 — Source 仓库不可用"
                elif grep -q 'different.*function\|code.*structure' "$BLOG" 2>/dev/null; then
                    warn "内核代码结构不同 — 该子版本可能已包含修复"
                    echo "  替代方案: nested=0 或 内核升级 7.1"
                else
                    warn "编译失败，详情: $BLOG"
                    grep -i 'error\|failed' "$BLOG" | tail -3
                fi
            fi

            # 检查文件是否已经被打 patch (打过了会报 "already patched")
            if grep -q 'already patched\|Reversed\|previously applied' "$BLOG" 2>/dev/null; then
                warn "补丁已经应用过了（可能内核自带修复）"
            fi

            # 恢复原始 repo 文件
            cp "$REPO_BAK"/*.repo /etc/yum.repos.d/ 2>/dev/null
            rm -rf "$REPO_BAK"
            kpatch-build --skip-compiler-check fix.patch 2>&1 | tail -10
            if ls kpatch-*.ko 2>/dev/null; then
                ok "补丁编译完成: $(ls kpatch-*.ko)"
                echo ""
                if [ -t 0 ]; then
                    read -p "  是否立即加载补丁? [y/N] " ans5
                else
                    read -p "  是否立即加载补丁? [y/N] " ans5 </dev/tty
                fi
                if [ "$ans5" = "y" ] || [ "$ans5" = "Y" ]; then
                    kpatch load kpatch-*.ko
                    ok "补丁已加载"
                    echo ""
                    if [ -t 0 ]; then
                        read -p "  是否运行环境检测验证补丁状态? [Y/n] " ans6
                    else
                        read -p "  是否运行环境检测验证补丁状态? [Y/n] " ans6 </dev/tty
                    fi
                    if [ "$ans6" != "n" ] && [ "$ans6" != "N" ]; then
                        detect_env
                    fi
                fi
            else
                warn "编译完成但未找到 .ko 文件，请检查编译日志"
            fi
            cd - >/dev/null
        else
            warn "补丁文件下载失败，手动执行:"
            echo "  kpatch-build --skip-compiler-check <patch-file>"
            echo "  详见: docs/kpatch-rhel8.md"
        fi
        rm -rf "$PATCHDIR"
    else
        echo "  手动执行: kpatch-build --skip-compiler-check <patch-file>"
        echo "  详见: docs/kpatch-rhel8.md"
    fi
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
    echo -e "  ${BOLD}操作${NC}"
    echo "  1) 集群审计                2) 崩溃日志取证"
    echo "  3) nested=0 一键关闭      4) ftrace 编译加载"
    if [ "$IS_RHEL8" -eq 1 ]; then
        echo "  5) kpatch 环境准备         6) 内核升级 7.1 指南"
        echo "  7) 查看完整文档"
        CHOICE_MAX=7
    else
        echo "  5) 内核升级 7.1 指南       6) 查看完整文档"
        CHOICE_MAX=6
    fi
    echo "  0) 退出"
    echo ""
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
                show_upgrade
            fi
            ;;
        6)
            if [ "$IS_RHEL8" -eq 1 ]; then
                show_upgrade
            else
                show_docs
            fi
            ;;
        7) show_docs ;;
        0) exit 0 ;;
        *) warn "无效选择" ;;
    esac
    echo ""
    # 清理子任务可能残留的 stdin 数据
    while read -t 0.1 -r _ 2>/dev/null; do :; done
    if [ -t 0 ]; then
        read -p "  按 Enter 返回主菜单 (输入 0 退出)..." PAUSE
    else
        read -p "  按 Enter 返回主菜单 (输入 0 退出)..." PAUSE </dev/tty
    fi
    [ "$PAUSE" = "0" ] && exit 0
}

show_upgrade() {
    echo ""
    echo "  内核升级 7.1 指南: docs/kernel-upgrade.md"
    echo "  快速步骤:"
    echo ""
    echo "  wget https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.1.3.tar.xz"
    echo "  tar xf linux-7.1.3.tar.xz && cd linux-7.1.3"
    echo "  zcat /proc/config.gz > .config || cp /boot/config-\$(uname -r) .config"
    echo "  scripts/config --disable MODULE_SIG --disable MODULE_SIG_FORCE"
    echo "  make olddefconfig"
    echo "  make -j\$(nproc) && make modules_install && make install"
    echo "  grubby --set-default /boot/vmlinuz-7.1.3 && reboot"
    echo ""
    echo "  完整步骤 & 常见错误: docs/kernel-upgrade.md"
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
    check_version
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
