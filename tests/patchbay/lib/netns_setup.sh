#!/bin/bash
# netns_setup.sh — patchbay 网络命名空间工具函数（T-LP2-002 公共库）
#
# 提供 NAT 类型模拟、网络损伤注入、命名空间管理的通用函数，
# 供各场景脚本（S1-S8）source 使用。
#
# NAT 类型实现：
#   - FullCone:   iptables SNAT --to-source（固定端口，任意外部主机可回连）
#   - Symmetric:  iptables MASQUERADE --random（每连接随机端口，仅目标可回连）
#   - PortRestricted: iptables SNAT + DROP 非目标端口回包
#
# 网络损伤：
#   - loss:    tc qdisc netem loss N%
#   - delay:   tc qdisc netem delay Nms
#   - reorder: tc qdisc netem delay Nms reorder N%
#   - corrupt: tc qdisc netem corrupt N%

set -euo pipefail

# ============================================================================
# 常量
# ============================================================================

# 命名空间前缀（避免与系统其他命名空间冲突）
readonly NS_PREFIX="pb-"

# 内部网段（用于命名空间间通信）
readonly INTERNAL_NET="10.99.0.0/16"
readonly INTERNAL_GW="10.99.0.254"

# macvlan 父接口名称（所有节点的 eth0 作为 macvlan bridge 模式接口共享此父接口，
# 实现命名空间间二层互通 — 比 Linux bridge 在 Docker 环境下更可靠）
readonly PARENT_DEV="pb-parent"

# macvlan 临时接口名计数器（接口名最大 15 字节，用计数器避免节点名过长）
_mv_counter=0

# ============================================================================
# 父接口管理（macvlan bridge 模式）
# ============================================================================

# 确保父接口存在并 UP（幂等，可重复调用）
_ensure_parent() {
    ip link add "$PARENT_DEV" type dummy 2>/dev/null || true
    ip link set "$PARENT_DEV" up
}

# 删除父接口
_delete_parent() {
    ip link del "$PARENT_DEV" 2>/dev/null || true
}

# ============================================================================
# 命名空间管理
# ============================================================================

# 创建网络命名空间
# 用法: ns_create <name> <ip_suffix>
#   name: 命名空间名（不含前缀，如 "node_a"）
#   ip_suffix: IP 地址最后一段（如 1 → 10.99.0.1）
#
# 拓扑: 每个 ns 的 eth0 是 macvlan (mode bridge) 接口，共享宿主机 dummy 父接口
#       (pb-parent)。所有 ns 在同一二层网络 10.99.0.0/16，ARP/UDP 直接互通。
#       选择 macvlan 而非 Linux bridge: Docker 环境下 bridge 受 nf_call/forward
#       限制容易丢包，macvlan bridge 模式纯二层转发更可靠。
ns_create() {
    local name="${1:?missing name}"
    local ip_suffix="${2:?missing ip_suffix}"
    local ns="${NS_PREFIX}${name}"
    local ip="10.99.0.${ip_suffix}"

    # 确保父接口存在
    _ensure_parent

    # 创建命名空间
    ip netns add "$ns" 2>/dev/null || true

    # 启用 loopback
    ip netns exec "$ns" ip link set lo up

    # 创建 macvlan 接口（bridge 模式），移入 ns 后重命名为 eth0
    # 注意: Linux 接口名最大 15 字节，用计数器避免节点名过长（如 relay_primary）导致创建失败
    _mv_counter=$((_mv_counter + 1))
    local mv_name="mv${_mv_counter}"
    ip link add link "$PARENT_DEV" name "$mv_name" type macvlan mode bridge 2>/dev/null || true
    ip link set "$mv_name" netns "$ns"
    ip netns exec "$ns" ip link set "$mv_name" name eth0 2>/dev/null || true

    # 配置 IP，默认路由（同 /16 直连，网关仅跨网段时用）
    ip netns exec "$ns" ip addr add "${ip}/16" dev eth0
    ip netns exec "$ns" ip link set eth0 up
    ip netns exec "$ns" ip route add default via "$INTERNAL_GW" 2>/dev/null || true

    # 开启命名空间内的转发
    ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1
    # 禁用 rp_filter（允许非对称路由）
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0
    ip netns exec "$ns" sysctl -qw net.ipv4.conf.default.rp_filter=0

    # 记录 IP 后缀映射（供 _get_ip_suffix 查询）
    _set_ip_suffix "$name" "$ip_suffix"

    echo "[netns] 创建 $ns ($ip)"
}

# 删除网络命名空间
# 用法: ns_delete <name>
ns_delete() {
    local name="${1:?missing name}"
    local ns="${NS_PREFIX}${name}"
    local veth_host="veth-${name}"

    ip netns del "$ns" 2>/dev/null || true
    ip link del "$veth_host" 2>/dev/null || true
    echo "[netns] 删除 $ns"
}

# 删除所有 patchbay 命名空间
ns_delete_all() {
    for ns in $(ip netns list | grep "^${NS_PREFIX}" | awk '{print $1}'); do
        ip netns del "$ns" 2>/dev/null || true
        local veth_host="${ns#${NS_PREFIX}}"
        ip link del "veth-${veth_host}" 2>/dev/null || true
    done
    # 删除父接口（所有 ns 已删，父接口无用）
    _delete_parent
    echo "[netns] 清理所有 patchbay 命名空间"
}

# 在命名空间中执行命令
# 用法: ns_exec <name> <command...>
ns_exec() {
    local name="${1:?missing name}"
    shift
    ip netns exec "${NS_PREFIX}${name}" "$@"
}

# ============================================================================
# NAT 类型配置
# ============================================================================

# 配置 FullCone NAT（固定端口，任意外部主机可回连）
# 用法: nat_fullcone <name>
nat_fullcone() {
    local name="${1:?missing name}"
    local ns="${NS_PREFIX}${name}"
    local ip="10.99.0.$(_get_ip_suffix "$name")"

    # 清除已有 nat 规则
    ip netns exec "$ns" iptables -t nat -F POSTROUTING 2>/dev/null || true
    # SNAT 固定源 IP（FullCone 语义：同一内部源 → 同一外部端口）
    ip netns exec "$ns" iptables -t nat -A POSTROUTING -s "${INTERNAL_NET}" -j SNAT --to-source "$ip"
    # 允许外部回连（FullCone 不限制来源）
    ip netns exec "$ns" iptables -P INPUT ACCEPT

    echo "[nat] $ns → FullCone ($ip)"
}

# 配置 Symmetric NAT（每连接随机端口，仅目标可回连）
# 用法: nat_symmetric <name>
nat_symmetric() {
    local name="${1:?missing name}"
    local ns="${NS_PREFIX}${name}"

    ip netns exec "$ns" iptables -t nat -F POSTROUTING 2>/dev/null || true
    # MASQUERADE --random 实现 Symmetric NAT（每连接随机端口）
    ip netns exec "$ns" iptables -t nat -A POSTROUTING -s "${INTERNAL_NET}" -j MASQUERADE --random
    # 限制回连（Symmetric NAT 仅允许已建立连接的回包）
    ip netns exec "$ns" iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip netns exec "$ns" iptables -A INPUT -j DROP

    echo "[nat] $ns → Symmetric"
}

# 配置 Port-Restricted NAT（仅允许特定端口回连）
# 用法: nat_port_restricted <name>
nat_port_restricted() {
    local name="${1:?missing name}"
    local ns="${NS_PREFIX}${name}"
    local ip="10.99.0.$(_get_ip_suffix "$name")"

    ip netns exec "$ns" iptables -t nat -F POSTROUTING 2>/dev/null || true
    ip netns exec "$ns" iptables -t nat -A POSTROUTING -s "${INTERNAL_NET}" -j SNAT --to-source "$ip"
    # 仅允许已建立连接的回包
    ip netns exec "$ns" iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    ip netns exec "$ns" iptables -A INPUT -j DROP

    echo "[nat] $ns → Port-Restricted ($ip)"
}

# ============================================================================
# 网络损伤注入
# ============================================================================

# 注入丢包
# 用法: inject_loss <name> <percent>
inject_loss() {
    local name="${1:?missing name}"
    local percent="${2:?missing percent}"
    local ns="${NS_PREFIX}${name}"

    ip netns exec "$ns" tc qdisc del dev eth0 root 2>/dev/null || true
    ip netns exec "$ns" tc qdisc add dev eth0 root netem loss "${percent}%"
    echo "[netem] $ns 丢包 ${percent}%"
}

# 注入延迟
# 用法: inject_delay <name> <ms>
inject_delay() {
    local name="${1:?missing name}"
    local ms="${2:?missing ms}"
    local ns="${NS_PREFIX}${name}"

    ip netns exec "$ns" tc qdisc del dev eth0 root 2>/dev/null || true
    ip netns exec "$ns" tc qdisc add dev eth0 root netem delay "${ms}ms"
    echo "[netem] $ns 延迟 ${ms}ms"
}

# 注入乱序（OOS）
# 用法: inject_reorder <name> <delay_ms> <percent>
inject_reorder() {
    local name="${1:?missing name}"
    local delay_ms="${2:?missing delay_ms}"
    local percent="${3:?missing percent}"
    local ns="${NS_PREFIX}${name}"

    ip netns exec "$ns" tc qdisc del dev eth0 root 2>/dev/null || true
    # delay + reorder：部分包延迟发送，造成乱序
    ip netns exec "$ns" tc qdisc add dev eth0 root netem delay "${delay_ms}ms" reorder "${percent}%"
    echo "[netem] $ns 乱序 ${percent}% (delay ${delay_ms}ms)"
}

# 注入丢包+延迟组合
# 用法: inject_loss_delay <name> <loss_percent> <delay_ms>
inject_loss_delay() {
    local name="${1:?missing name}"
    local loss_percent="${2:?missing loss_percent}"
    local delay_ms="${3:?missing delay_ms}"
    local ns="${NS_PREFIX}${name}"

    ip netns exec "$ns" tc qdisc del dev eth0 root 2>/dev/null || true
    ip netns exec "$ns" tc qdisc add dev eth0 root netem loss "${loss_percent}%" delay "${delay_ms}ms"
    echo "[netem] $ns 丢包 ${loss_percent}% + 延迟 ${delay_ms}ms"
}

# 清除网络损伤
# 用法: inject_clear <name>
inject_clear() {
    local name="${1:?missing name}"
    local ns="${NS_PREFIX}${name}"
    ip netns exec "$ns" tc qdisc del dev eth0 root 2>/dev/null || true
    echo "[netem] $ns 清除损伤"
}

# ============================================================================
# 网络切换模拟
# ============================================================================

# 模拟 IP 变化（网络切换）
# 用法: simulate_network_change <name> <new_ip_suffix>
simulate_network_change() {
    local name="${1:?missing name}"
    local new_suffix="${2:?missing new_ip_suffix}"
    local ns="${NS_PREFIX}${name}"
    local old_ip="10.99.0.$(_get_ip_suffix "$name")"
    local new_ip="10.99.0.${new_suffix}"

    # 移除旧 IP，添加新 IP
    ip netns exec "$ns" ip addr del "${old_ip}/16" dev eth0 2>/dev/null || true
    ip netns exec "$ns" ip addr add "${new_ip}/16" dev eth0

    # 更新 IP 映射
    _set_ip_suffix "$name" "$new_suffix"

    echo "[net-change] $ns IP: $old_ip → $new_ip"
}

# ============================================================================
# 辅助函数
# ============================================================================

# 获取命名空间的 IP 后缀（从关联文件读取）
_get_ip_suffix() {
    local name="$1"
    local map_file="/tmp/patchbay_ip_map"
    if [[ -f "$map_file" ]]; then
        grep "^${name}=" "$map_file" 2>/dev/null | cut -d= -f2 || echo "1"
    else
        echo "1"
    fi
}

# 设置命名空间的 IP 后缀
_set_ip_suffix() {
    local name="$1"
    local suffix="$2"
    local map_file="/tmp/patchbay_ip_map"
    # 删除旧记录，添加新记录
    sed -i "/^${name}=/d" "$map_file" 2>/dev/null || true
    echo "${name}=${suffix}" >> "$map_file"
}

# 等待条件满足
# 用法: wait_for <description> <timeout_sec> <check_command...>
wait_for() {
    local desc="$1"
    local timeout="$2"
    shift 2
    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    echo "[timeout] 等待超时: $desc (${timeout}s)"
    return 1
}

# ============================================================================
# 清理函数（trap 使用）
# ============================================================================

patchbay_cleanup() {
    echo "[cleanup] 开始清理..."
    ns_delete_all
    rm -f /tmp/patchbay_ip_map
    echo "[cleanup] 完成"
}
