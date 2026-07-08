#!/bin/bash
# Januscape (CVE-2026-53359) 宿主机排查脚本
# 检测嵌套虚拟化状态、上游补丁、运行中 VM，并给出操作建议。

echo "=== Januscape 宿主机排查 ==="
echo "Host: $(hostname) | Kernel: $(uname -r)"
echo

echo "--- 嵌套虚拟化 ---"
for f in /sys/module/kvm_intel/parameters/nested /sys/module/kvm_amd/parameters/nested; do
    [ -f "$f" ] && echo "$f = $(cat $f)" || true
done

echo -e "\n--- 补丁状态 ---"
if grep -q 'role.word' /proc/kallsyms 2>/dev/null; then
    echo "✅ 上游补丁已打 (role.word in kallsyms)"
else
    echo "❌ 未打上游补丁 — 需要 hotfix 或 nested=0"
fi

echo -e "\n--- 运行中的 VM ---"
virsh list 2>/dev/null | sed 's/^/  /'
[ $? -ne 0 ] && echo "  无 libvirt"

echo -e "\n--- QEMU 进程 ---"
QEMU=$(ps aux | grep -c '[q]emu' || echo 0)
echo "  qemu 进程数: $QEMU"

echo -e "\n--- KVM 模块 ---"
lsmod | grep kvm | sed 's/^/  /'

echo -e "\n=== 建议 ==="
if grep -q 'role.word' /proc/kallsyms 2>/dev/null; then
    echo "✅ 已打补丁，无需操作"
else
    NESTED=$(cat /sys/module/kvm_intel/parameters/nested 2>/dev/null || cat /sys/module/kvm_amd/parameters/nested 2>/dev/null || echo 0)
    if [ "$NESTED" = "0" ] || [ "$NESTED" = "N" ]; then
        echo "✅ nested=0 已关闭嵌套，攻击面不存在"
    else
        VMS=$(virsh list --name 2>/dev/null | grep -c .)
        [ "$VMS" -eq 0 ] 2>/dev/null && VMS=$QEMU
        if [ "$VMS" -eq 0 ]; then
            echo "⚡ 无运行 VM → 直接重载 kvm 关嵌套"
        else
            echo "⚠️  $VMS 台 VM 在跑 + nested=1 → 需要 hotfix 或关机重载"
        fi
    fi
fi
