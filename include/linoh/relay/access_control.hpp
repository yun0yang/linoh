// access_control.hpp — Relay 访问控制接口（P4-C-1）
//
// 借鉴 iroh PR #4276（Replace AccessConfig enum with AccessControl trait）
// 和 iroh PR #4326（Add Bearer token access control）：
//   - 抽象 AccessControl 接口（替代硬编码 AccessConfig 枚举）
//   - BearerTokenAccessControl：通过 HTTP Authorization 头校验
//   - Ed25519ChallengeAccessControl：原有 challenge-response 流程
//   - ChainedAccessControl：多策略组合（任一 Allow 即通过）
//
// 与现有 auth.hpp 的关系：
//   - auth.hpp 定义协议级帧编解码（ServerChallenge/ClientAuth）
//   - access_control.hpp 定义策略层（决定是否接受某个客户端）
//   - server.cpp 在握手前调用 AccessControl::verify_client

#pragma once

#include "linoh/base/endpoint_addr.hpp"
#include "linoh/base/key.hpp"
#include "linoh/relay/auth.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace linoh::relay {

/// 访问控制决策（借鉴 iroh AccessControl trait）
enum class Decision {
    Allow,      // 直接放行
    Deny,       // 直接拒绝
    Challenge,  // 要求 challenge-response 流程
};

/// 客户端连接请求信息
///
/// server 在握手阶段收集这些信息后调用 verify_client。
struct ClientRequest {
    /// 客户端 IP 地址和端口（来自 accept 后的 socket peer addr）
    base::TransportAddr peer_addr;

    /// 客户端声称的目标 host（HTTP Host 头 / WS target）
    std::string target_host;

    /// Bearer token（HTTP Authorization: Bearer xxx）
    /// 由 iroh PR #4326 引入，可选
    std::optional<std::string> bearer_token;

    /// 客户端 EndpointId（如果已通过 challenge-response 提供）
    std::optional<base::EndpointId> endpoint_id;

    /// 客户端对 challenge 的签名（如果已通过 challenge-response 提供）
    std::optional<base::Signature> challenge_response;

    /// 查询参数（WS URL query string，例如 ?token=xxx）
    std::unordered_map<std::string, std::string> query_params;
};

/// 访问控制接口（借鉴 iroh AccessControl trait）
class AccessControl {
public:
    virtual ~AccessControl() = default;

    /// 验证客户端连接请求
    ///
    /// @return Decision::Allow 直接放行
    ///         Decision::Deny 直接拒绝
    ///         Decision::Challenge 要求执行 challenge-response 流程
    virtual Decision verify_client(const ClientRequest &req) = 0;

    /// 策略名称（用于日志和诊断）
    virtual std::string_view name() const = 0;
};

/// 始终放行（用于测试或无访问控制场景）
class AllowAllAccessControl : public AccessControl {
public:
    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "allow-all"; }
};

/// 始终拒绝（用于安全敏感场景的默认拒绝）
class DenyAllAccessControl : public AccessControl {
public:
    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "deny-all"; }
};

/// Bearer token 访问控制（借鉴 iroh PR #4326）
///
/// 客户端在 HTTP Authorization 头或 query 参数 ?token=xxx 中携带 token。
/// 使用常量时间比较防止时序攻击。
class BearerTokenAccessControl : public AccessControl {
public:
    /// @param expected_token 期望的 token 字符串
    explicit BearerTokenAccessControl(std::string expected_token);

    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "bearer-token"; }

    /// 配置 query 参数名（默认 "token"）
    void set_query_param_name(std::string name) { query_param_name_ = std::move(name); }

private:
    std::string expected_token_;
    std::string query_param_name_{"token"};
};

/// IP 白名单访问控制
///
/// 仅允许指定 IP 集合的客户端连接，其他客户端直接拒绝。
class IpAllowlistAccessControl : public AccessControl {
public:
    /// @param allowed_ips 允许的 IP 字符串列表（如 "10.0.0.1", "192.168.1.0/24"）
    ///        简化实现：仅支持单 IP，不支持 CIDR
    explicit IpAllowlistAccessControl(std::vector<std::string> allowed_ips);

    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "ip-allowlist"; }

    /// 新增允许的 IP
    void add_ip(std::string ip) { allowed_ips_.push_back(std::move(ip)); }

private:
    std::vector<std::string> allowed_ips_;
};

/// Ed25519 challenge-response 访问控制（保留原有认证逻辑）
///
/// 始终返回 Decision::Challenge，由 server 执行实际签名验证。
/// 配合 server::do_handshake() 使用。
class Ed25519ChallengeAccessControl : public AccessControl {
public:
    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "ed25519-challenge"; }

    /// 配置已知的 endpoint_id 集合（白名单模式）
    /// 若集合非空，则仅允许这些 endpoint_id 通过 challenge-response
    void set_allowed_endpoints(std::vector<base::EndpointId> endpoints) {
        allowed_endpoints_ = std::move(endpoints);
    }

    /// 校验 ClientAuth 是否在白名单内（若白名单非空）
    bool is_endpoint_allowed(const base::EndpointId &id) const;

private:
    std::vector<base::EndpointId> allowed_endpoints_;
};

/// 组合策略：按顺序调用，任一 Allow 即返回 Allow
///
/// 注意：若所有策略都返回 Challenge，则整体返回 Challenge；
/// 若任一返回 Deny，则整体返回 Deny（除非前面有 Allow）。
/// 推荐顺序：[AllowAll] → [BearerToken] → [Ed25519Challenge] → [DenyAll]
class ChainedAccessControl : public AccessControl {
public:
    /// 添加子策略（顺序敏感）
    ChainedAccessControl &add(std::shared_ptr<AccessControl> ac);

    Decision verify_client(const ClientRequest &req) override;
    std::string_view name() const override { return "chained"; }

    /// 子策略数量
    std::size_t size() const { return chain_.size(); }

    /// 是否为空
    bool empty() const { return chain_.empty(); }

private:
    std::vector<std::shared_ptr<AccessControl>> chain_;
};

/// 工厂函数：按名称创建访问控制策略
/// @param name "allow-all" / "deny-all" / "bearer-token" / "ed25519-challenge"
/// @param arg 可选参数（如 bearer-token 的 token 字符串）
/// @return 对应的策略实例，未知名称返回 nullptr
std::shared_ptr<AccessControl> create_access_control_by_name(
    std::string_view name, const std::string &arg = "");

} // namespace linoh::relay
