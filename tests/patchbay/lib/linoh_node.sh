#!/bin/bash
# linoh_node.sh — patchbay linoh 节点管理工具（T-LP2-002 公共库）
#
# 提供在网络命名空间中启动/停止/检查 linoh 测试节点的通用函数。
# 依赖环境变量：
#   LINOH_BIN  — linoh 构建目录（含测试二进制）
#   PATCHBAY_DIR — patchbay 脚本目录
#
# 测试节点模式：
#   1. echo 模式：节点 A 连接节点 B，发送数据，B 回显，A 验证
#   2. relay 模式：节点通过 relay 服务器中转连接
#   3. PP 链模式：5 节点菊花链端到端推理（S8 专用）

set -euo pipefail

# ============================================================================
# 常量
# ============================================================================

# 从环境变量获取 linoh 构建目录
LINOH_BIN="${LINOH_BIN:-/opt/linoh/build}"
PATCHBAY_DIR="${PATCHBAY_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

# linoh 测试二进制（echo 节点）
LINOH_ECHO_NODE="${LINOH_BIN}/linoh_echo_node"
# linoh relay 服务器
LINOH_RELAY="${LINOH_BIN}/linoh-relay-server"
# linoh e2e 测试
LINOH_E2E_TEST="${LINOH_BIN}/e2e_endpoint_id_test"

# 节点 PID 文件目录
PID_DIR="/tmp/patchbay_pids"
mkdir -p "$PID_DIR" 2>/dev/null || true

# 日志目录
LOG_DIR="/tmp/patchbay_logs"
mkdir -p "$LOG_DIR" 2>/dev/null || true

# ============================================================================
# 节点管理
# ============================================================================

# 在命名空间中启动 linoh echo 节点
# 用法: node_start_echo <ns_name> <port> <role> [remote_ns_name] [extra_args...]
#   role: "server" 或 "client"
#   remote_ns_name: client 模式下指定 server 的命名空间名（用于推导 IP）
#   extra_args: 传递给 echo_node 的额外参数（如 --mode continuous --interval 1）
node_start_echo() {
    local ns_name="${1:?missing ns_name}"
    local port="${2:?missing port}"
    local role="${3:?missing role}"
    local remote_ns="${4:-}"
    # 移除前 min($#, 4) 个位置参数，剩余作为 extra_args
    # 注意: 当调用方未传 remote_ns（仅 3 个参数）时，shift 4 会失败，
    #       需回退为 shift 3，避免 extra_args 误包含 ns_name/port/role
    if [[ $# -ge 4 ]]; then
        shift 4
    elif [[ $# -ge 3 ]]; then
        shift 3
    fi
    local extra_args=("$@")
    local ns="pb-${ns_name}"
    local pid_file="${PID_DIR}/${ns_name}.pid"
    local log_file="${LOG_DIR}/${ns_name}.log"

    # 检查二进制是否存在
    if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
        echo "[ERROR] echo 节点二进制不存在: $LINOH_ECHO_NODE"
        echo "[HINT]  请确保 linoh 已编译，或通过 LINOH_BIN 环境变量指定路径"
        return 1
    fi

    # 构建参数
    local args=("--port" "$port" "--role" "$role" "--log" "$log_file")
    if [[ "$role" == "client" && -n "$remote_ns" ]]; then
        # 从命名空间名推导 server IP（10.99.0.{suffix}）
        local remote_ip="10.99.0.$(_get_ip_suffix "$remote_ns")"
        args+=("--remote-ip" "$remote_ip" "--remote-port" "$port")
        echo "[node] client 将连接到 ${remote_ip}:${port}"
    fi
    # 附加额外参数（如 --mode continuous --interval 1）
    if [[ ${#extra_args[@]} -gt 0 ]]; then
        args+=("${extra_args[@]}")
        echo "[node] extra args: ${extra_args[*]}"
    fi

    # 在命名空间中启动
    ip netns exec "$ns" "$LINOH_ECHO_NODE" "${args[@]}" &
    local pid=$!
    echo "$pid" > "$pid_file"

    echo "[node] 启动 ${ns_name} ($role) port=$port pid=$pid"
    return 0
}

# 启动 relay 服务器
# 用法: node_start_relay <ns_name> <port>
# 启动后同步等待 relay 输出 listening 标记（最多 5s），并向日志追加标准 LISTENING 标记
# 便于场景脚本通过 node_wait_ready "xxx" "LISTENING" 检测就绪
node_start_relay() {
    local ns_name="${1:?missing ns_name}"
    local port="${2:?missing port}"
    local ns="pb-${ns_name}"
    local pid_file="${PID_DIR}/${ns_name}.pid"
    local log_file="${LOG_DIR}/${ns_name}.log"

    if [[ ! -f "$LINOH_RELAY" ]]; then
        echo "[ERROR] relay 二进制不存在: $LINOH_RELAY"
        return 1
    fi

    # 清空旧日志
    : > "$log_file"

    ip netns exec "$ns" "$LINOH_RELAY" --port "$port" > "$log_file" 2>&1 &
    local pid=$!
    echo "$pid" > "$pid_file"

    echo "[relay] 启动 ${ns_name} port=$port pid=$pid"

    # 同步等待 relay 输出 listening 标记（最多 5s，10 次 * 0.5s 轮询）
    # relay 服务器日志格式: "[INFO ] RelayServer: listening on port N"
    local tick=0
    while [[ $tick -lt 10 ]]; do
        if grep -q "listening" "$log_file" 2>/dev/null; then
            # 追加标准 LISTENING 标记，统一与 echo_node 的就绪标记
            echo "LISTENING" >> "$log_file"
            echo "[relay] ${ns_name} 已就绪 (LISTENING)"
            return 0
        fi
        # 检查 bind 失败
        if grep -q "bind() failed\|failed to bind" "$log_file" 2>/dev/null; then
            echo "[ERROR] relay ${ns_name} bind 端口 ${port} 失败"
            cat "$log_file" | tail -5
            return 1
        fi
        sleep 0.5
        tick=$((tick + 1))
    done

    echo "[WARN] relay ${ns_name} 未在 5s 内输出 listening 标记"
    return 0
}

# 停止节点
# 用法: node_stop <ns_name>
node_stop() {
    local ns_name="${1:?missing ns_name}"
    local pid_file="${PID_DIR}/${ns_name}.pid"

    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            sleep 0.5
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
        echo "[node] 停止 ${ns_name} (pid=$pid)"
    fi
}

# 停止所有节点
node_stop_all() {
    for pid_file in "${PID_DIR}"/*.pid; do
        [[ -f "$pid_file" ]] || continue
        local ns_name
        ns_name=$(basename "$pid_file" .pid)
        node_stop "$ns_name"
    done
}

# 检查节点是否存活
# 用法: node_is_alive <ns_name>
node_is_alive() {
    local ns_name="${1:?missing ns_name}"
    local pid_file="${PID_DIR}/${ns_name}.pid"
    if [[ ! -f "$pid_file" ]]; then
        return 1
    fi
    local pid
    pid=$(cat "$pid_file")
    kill -0 "$pid" 2>/dev/null
}

# 等待节点就绪（日志中出现特定标记）
# 用法: node_wait_ready <ns_name> <marker> <timeout_sec>
node_wait_ready() {
    local ns_name="${1:?missing ns_name}"
    local marker="${2:?missing marker}"
    local timeout="${3:-30}"
    local log_file="${LOG_DIR}/${ns_name}.log"

    local elapsed=0
    while [[ $elapsed -lt $timeout ]]; do
        if [[ -f "$log_file" ]] && grep -q "$marker" "$log_file" 2>/dev/null; then
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    echo "[timeout] ${ns_name} 未在 ${timeout}s 内就绪（等待标记: $marker）"
    return 1
}

# 检查日志中是否包含指定内容
# 用法: node_log_contains <ns_name> <pattern>
node_log_contains() {
    local ns_name="${1:?missing ns_name}"
    local pattern="${2:?missing pattern}"
    local log_file="${LOG_DIR}/${ns_name}.log"
    [[ -f "$log_file" ]] && grep -q "$pattern" "$log_file" 2>/dev/null
}

# 获取节点日志
# 用法: node_get_log <ns_name>
node_get_log() {
    local ns_name="${1:?missing ns_name}"
    local log_file="${LOG_DIR}/${ns_name}.log"
    if [[ -f "$log_file" ]]; then
        cat "$log_file"
    fi
}

# ============================================================================
# 连接验证
# ============================================================================

# 验证两个节点成功建立 linoh 连接
# 用法: verify_connection <client_name> <server_name> <timeout_sec>
verify_connection() {
    local client_name="${1:?missing client_name}"
    local server_name="${2:?missing server_name}"
    local timeout="${3:-60}"

    echo "[verify] 检查 ${client_name} → ${server_name} 连接..."

    # 检查客户端日志中是否有连接成功标记
    if node_wait_ready "$client_name" "CONNECTED" "$timeout"; then
        echo "[verify] ${client_name} → ${server_name} 连接成功"
        return 0
    else
        echo "[verify] ${client_name} → ${server_name} 连接失败"
        echo "  --- client log (tail) ---"
        node_get_log "$client_name" 2>/dev/null | tail -10 | sed 's/^/  /'
        echo "  --- server log (tail) ---"
        node_get_log "$server_name" 2>/dev/null | tail -10 | sed 's/^/  /'
        return 1
    fi
}

# 验证数据传输成功
# 用法: verify_data_transfer <client_name> <timeout_sec>
verify_data_transfer() {
    local client_name="${1:?missing client_name}"
    local timeout="${2:-60}"

    echo "[verify] 检查 ${client_name} 数据传输..."

    if node_wait_ready "$client_name" "ECHO_OK" "$timeout"; then
        echo "[verify] ${client_name} 数据传输成功"
        return 0
    else
        echo "[verify] ${client_name} 数据传输失败"
        return 1
    fi
}

# ============================================================================
# K-LP-001: Relay 模式支持（双向 Symmetric NAT relay 中转）
# ============================================================================

# 启动 relay 模式 echo 节点（server 或 client）
# 用法: node_start_relay_echo <ns_name> <role> <relay_addr> [peer_endpoint_id] [extra_args...]
#   role: "server" 或 "client"
#   relay_addr: relay 服务器地址 (host:port)
#   peer_endpoint_id: client 模式下指定 server 的 EndpointId（64 字符 hex）
node_start_relay_echo() {
    local ns_name="${1:?missing ns_name}"
    local role="${2:?missing role}"
    local relay_addr="${3:?missing relay_addr}"
    local peer_eid="${4:-}"
    if [[ $# -ge 4 ]]; then shift 4; elif [[ $# -ge 3 ]]; then shift 3; fi
    local extra_args=("$@")
    local ns="pb-${ns_name}"
    local pid_file="${PID_DIR}/${ns_name}.pid"
    local log_file="${LOG_DIR}/${ns_name}.log"

    if [[ ! -f "$LINOH_ECHO_NODE" ]]; then
        echo "[ERROR] echo 节点二进制不存在: $LINOH_ECHO_NODE"
        return 1
    fi

    # 清空旧日志
    : > "$log_file"

    local args=("--role" "$role" "--relay-addr" "$relay_addr" "--log" "$log_file")
    if [[ "$role" == "client" && -n "$peer_eid" ]]; then
        args+=("--peer-endpoint-id" "$peer_eid")
    fi
    if [[ ${#extra_args[@]} -gt 0 ]]; then
        args+=("${extra_args[@]}")
    fi

    ip netns exec "$ns" "$LINOH_ECHO_NODE" "${args[@]}" &
    local pid=$!
    echo "$pid" > "$pid_file"

    echo "[node] 启动 ${ns_name} (relay ${role}) relay=${relay_addr} pid=$pid"
    return 0
}

# 从节点日志中提取 endpoint_id
# 用法: node_get_endpoint_id <ns_name>
# 输出: 64 字符 hex 字符串，失败返回空
node_get_endpoint_id() {
    local ns_name="${1:?missing ns_name}"
    local log_file="${LOG_DIR}/${ns_name}.log"
    if [[ ! -f "$log_file" ]]; then
        echo ""
        return 1
    fi
    # 日志格式: endpoint_id=<64 hex chars>
    grep -oP 'endpoint_id=\K[0-9a-f]{64}' "$log_file" 2>/dev/null | head -1
}

# ============================================================================
# 清理
# ============================================================================

linoh_node_cleanup() {
    node_stop_all
    rm -rf "$PID_DIR" "$LOG_DIR" 2>/dev/null || true
}
