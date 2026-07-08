#!/bin/bash
# Januscape (CVE-2026-53359) 日志排查脚本
# 检查上次启动日志中是否有 Januscape panic 痕迹。

echo "=== Januscape 日志排查 ==="
echo "Host: $(hostname) | $(date)"
echo

echo "--- 重启记录 ---"
last reboot | head -10 | sed 's/^/  /'

echo -e "\n--- Januscape 特征 panic ---"

LOGBUF=$(journalctl -k -b -1 --no-pager 2>/dev/null)

if [ -z "$LOGBUF" ]; then
    echo "  (无上次启动日志)"
else
    GFN=$(echo "$LOGBUF" | grep -c 'gfn mismatch')
    PTL=$(echo "$LOGBUF" | grep -c 'pte_list_remove')
    COR=$(echo "$LOGBUF" | grep -c 'KVM_BUG_ON_DATA_CORRUPTION')
    MMU=$(echo "$LOGBUF" | grep -c 'BUG.*mmu/mmu.c')

    [ "$GFN" -gt 0 ] 2>/dev/null && echo "  ❌ gfn mismatch → $GFN 命中!" && FOUND=1
    [ "$PTL" -gt 0 ] 2>/dev/null && echo "  ❌ pte_list_remove → $PTL 命中!" && FOUND=1
    [ "$COR" -gt 0 ] 2>/dev/null && echo "  ❌ KVM_BUG_ON_DATA_CORRUPTION → $COR 命中!" && FOUND=1
    [ "$MMU" -gt 0 ] 2>/dev/null && echo "  ❌ BUG in mmu/mmu.c → $MMU 命中!" && FOUND=1

    [ "${FOUND:-0}" -eq 0 ] && echo "  ✅ 无 Januscape 特征"
fi

echo -e "\n--- 上次启动 Kernel Panic / Oops ---"
if [ -n "$LOGBUF" ]; then
    echo "$LOGBUF" | grep -iE 'Kernel panic|Oops:|BUG:.*not tainted' | tail -3 | sed 's/^/  /'
    echo "$LOGBUF" | grep -qiE 'Kernel panic|Oops:|BUG:.*not tainted' || echo "  无"
else
    echo "  无 (或 journald 不存旧日志)"
fi

echo -e "\n--- 当前启动 KVM 异常 ---"
dmesg 2>/dev/null | grep -iE 'gfn mismatch|KVM.*BUG|kvm.*corrupt' | tail -5 | sed 's/^/  /'
dmesg 2>/dev/null | grep -qiE 'gfn mismatch|KVM.*BUG|kvm.*corrupt' || echo "  无"

echo -e "\n--- 硬件错误 ---"
MCE=$(dmesg 2>/dev/null | grep -ciE 'Machine Check|mce:')
AER=$(dmesg 2>/dev/null | grep -ci 'AER:')
echo "  MCE: $MCE 条 | AER: $AER 条"
[ "$AER" -gt 50 ] 2>/dev/null && echo "  ⚠️  AER 过多，排查 PCIe 硬件"

echo -e "\n=== 综合判定 ==="
if [ "${FOUND:-0}" -eq 1 ]; then
    echo "❌ 此宿主机可能已被 Januscape 攻击过!"
    echo "   详情:"
    echo "$LOGBUF" | grep -A5 'gfn mismatch\|pte_list_remove' | head -20
elif [ -z "$LOGBUF" ]; then
    echo "⚡ 无法读取上次启动日志"
else
    echo "✅ 日志中无 Januscape panic 痕迹"
fi
