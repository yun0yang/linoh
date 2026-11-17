// access_control.cpp — Relay 访问控制实现（P4-C-1）

#include "linoh/relay/access_control.hpp"
#include "linoh/util/crypto.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <cstring>

namespace linoh::relay {

// ============================================================================
// AllowAllAccessControl
// ============================================================================

Decision AllowAllAccessControl::verify_client(const ClientRequest &req) {
    (void)req;
    LINOH_DEBUG("AllowAll: ", name());
    return Decision::Allow;
}

// ============================================================================
// DenyAllAccessControl
// ============================================================================

Decision DenyAllAccessControl::verify_client(const ClientRequest &req) {
    (void)req;
    LINOH_DEBUG("DenyAll: ", name());
    return Decision::Deny;
}

// ============================================================================
// BearerTokenAccessControl
// ============================================================================

BearerTokenAccessControl::BearerTokenAccessControl(std::string expected_token)
    : expected_token_(std::move(expected_token)) {}

Decision BearerTokenAccessControl::verify_client(const ClientRequest &req) {
    // 优先使用 Authorization: Bearer xxx
    std::string provided;
    if (req.bearer_token && !req.bearer_token->empty()) {
        provided = *req.bearer_token;
    } else {
        // 回退到 query 参数 ?token=xxx
        auto it = req.query_params.find(query_param_name_);
        if (it != req.query_params.end()) {
            provided = it->second;
        }
    }

    if (provided.empty()) {
        LINOH_DEBUG("BearerToken: no token provided");
        return Decision::Deny;
    }

    // 常量时间比较防止时序攻击
    std::span<const uint8_t> a(
        reinterpret_cast<const uint8_t *>(provided.data()),
        provided.size());
    std::span<const uint8_t> b(
        reinterpret_cast<const uint8_t *>(expected_token_.data()),
        expected_token_.size());

    if (crypto::verify_equal(a, b)) {
        LINOH_DEBUG("BearerToken: verified");
        return Decision::Allow;
    }

    LINOH_DEBUG("BearerToken: token mismatch");
    return Decision::Deny;
}

// ============================================================================
// IpAllowlistAccessControl
// ============================================================================

IpAllowlistAccessControl::IpAllowlistAccessControl(std::vector<std::string> allowed_ips)
    : allowed_ips_(std::move(allowed_ips)) {}

Decision IpAllowlistAccessControl::verify_client(const ClientRequest &req) {
    if (allowed_ips_.empty()) {
        // 空白名单 = 全部拒绝（保守）
        LINOH_DEBUG("IpAllowlist: empty allowlist, deny");
        return Decision::Deny;
    }

    const std::string &client_ip = req.peer_addr.host;
    for (const auto &allowed : allowed_ips_) {
        if (client_ip == allowed) {
            LINOH_DEBUG("IpAllowlist: ", client_ip, " allowed");
            return Decision::Allow;
        }
    }

    LINOH_DEBUG("IpAllowlist: ", client_ip, " not in allowlist");
    return Decision::Deny;
}

// ============================================================================
// Ed25519ChallengeAccessControl
// ============================================================================

Decision Ed25519ChallengeAccessControl::verify_client(const ClientRequest &req) {
    (void)req;
    // 始终要求 challenge-response，由 server 执行实际签名验证
    return Decision::Challenge;
}

bool Ed25519ChallengeAccessControl::is_endpoint_allowed(
    const base::EndpointId &id) const {
    if (allowed_endpoints_.empty()) return true;  // 白名单为空 = 允许所有
    for (const auto &allowed : allowed_endpoints_) {
        if (id == allowed) return true;
    }
    return false;
}

// ============================================================================
// ChainedAccessControl
// ============================================================================

ChainedAccessControl &ChainedAccessControl::add(std::shared_ptr<AccessControl> ac) {
    if (ac) {
        chain_.push_back(std::move(ac));
    }
    return *this;
}

Decision ChainedAccessControl::verify_client(const ClientRequest &req) {
    // iroh ChainedAccessControl 语义：OR 组合（任一 Allow 即 Allow）
    // 优先级：Allow（任一即返回）> Deny（无 Allow 时返回）> Challenge（无 Allow/Deny 时返回）
    bool any_deny = false;
    bool any_challenge = false;

    for (auto &ac : chain_) {
        Decision d = ac->verify_client(req);
        switch (d) {
            case Decision::Allow:
                LINOH_DEBUG("Chained: '", ac->name(), "' allowed");
                return Decision::Allow;
            case Decision::Deny:
                any_deny = true;
                LINOH_DEBUG("Chained: '", ac->name(), "' denied (continue)");
                break;
            case Decision::Challenge:
                any_challenge = true;
                LINOH_DEBUG("Chained: '", ac->name(), "' challenge (continue)");
                break;
        }
    }

    // 没有 Allow：优先 Deny，其次 Challenge
    if (any_deny) {
        LINOH_DEBUG("Chained: no allow, but has deny, deny");
        return Decision::Deny;
    }
    if (any_challenge) {
        LINOH_DEBUG("Chained: no allow, no deny, has challenge, challenge");
        return Decision::Challenge;
    }

    // 所有策略都没有明确决策（理论上不会发生，但保守拒绝）
    LINOH_WARN("Chained: no decision from any strategy, deny by default");
    return Decision::Deny;
}

// ============================================================================
// 工厂函数
// ============================================================================

std::shared_ptr<AccessControl> create_access_control_by_name(
    std::string_view name, const std::string &arg) {
    if (name == "allow-all") {
        return std::make_shared<AllowAllAccessControl>();
    } else if (name == "deny-all") {
        return std::make_shared<DenyAllAccessControl>();
    } else if (name == "bearer-token") {
        return std::make_shared<BearerTokenAccessControl>(arg);
    } else if (name == "ed25519-challenge") {
        return std::make_shared<Ed25519ChallengeAccessControl>();
    }
    LINOH_WARN("create_access_control_by_name: unknown '", name, "'");
    return nullptr;
}

} // namespace linoh::relay
