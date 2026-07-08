# 关闭嵌套虚拟化（nested=0）

**最简单、最安全**的缓解方案。关闭 KVM 嵌套虚拟化后，L1 虚拟机无法使用
裸 VMX/SVM 指令运行 L2 嵌套虚拟机，漏洞路径（shadow MMU 的嵌套 EPT/NPT
影子化）永远不会被触发。

## 是否适用

**适用**：你的 VPS 租户不需要在虚拟机里运行嵌套虚拟机（K8s in VM、WSL2、
Android 模拟器等）。这覆盖 99% 的普通 VPS 使用场景。

**不适用**：你的业务需要暴露嵌套虚拟化给租户。

## 操作

### Intel 宿主机

```bash
echo "options kvm_intel nested=0" > /etc/modprobe.d/disable-nested.conf
```

### AMD 宿主机

```bash
echo "options kvm_amd nested=0" > /etc/modprobe.d/disable-nested.conf
```

### 立即生效

```bash
# 1. 关机所有虚拟机
virsh list --name | xargs -I{} virsh shutdown {}

# 2. 重载 KVM 模块
rmmod kvm_intel && modprobe kvm_intel nested=0   # Intel
rmmod kvm_amd   && modprobe kvm_amd nested=0     # AMD

# 3. 验证
cat /sys/module/kvm_intel/parameters/nested  # → N 或 0
cat /sys/module/kvm_amd/parameters/nested    # → 0

# 4. 开机虚拟机
```

如果当前无法停机，只写 `/etc/modprobe.d/disable-nested.conf` 即可——
下次重启自动生效。

## 验证

```bash
# Intel
grep -r nested /sys/module/kvm_intel/parameters/
# AMD
grep -r nested /sys/module/kvm_amd/parameters/
```

## 代价

| 受影响 | 不受影响 |
|--------|---------|
| VM 里跑 QEMU/KVM（嵌套虚拟化） | 普通 Docker/Podman 容器 |
| VM 里跑 WSL2 / Hyper-V | LXC / LXD |
| VM 里跑 Android Emulator | 常规 Web/DB/App 工作负载 |
| KubeVirt / Kata Containers | 普通 Kubernetes 容器运行时 |
