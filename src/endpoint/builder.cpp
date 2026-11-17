#include "linoh/endpoint/builder.hpp"

#include "linoh/util/logging.hpp"

namespace linoh::endpoint {

std::shared_ptr<Endpoint> Builder::build(linoh_asio::io_context &ctx) {
    if (cfg_.secret_key.is_zero()) {
        cfg_.secret_key = SecretKey::generate();
        LINOH_INFO("Builder: generated new secret key");
    }
    if (!cfg_.lookup) {
        cfg_.lookup = std::make_shared<address_lookup::MemoryLookup>();
    }

    // P4-D-3: 若 lookup 是 DnsAddressLookup，把 fallback 配置应用上去
    if (!dns_fallback_servers_.empty() || dns_query_timeout_ms_ != 500 || dns_max_retries_ != 3) {
        auto dns_lookup = std::dynamic_pointer_cast<address_lookup::DnsAddressLookup>(cfg_.lookup);
        if (dns_lookup) {
            for (const auto &s : dns_fallback_servers_) {
                dns_lookup->add_fallback_server(s.host, s.port);
            }
            dns_lookup->set_query_timeout_ms(dns_query_timeout_ms_);
            dns_lookup->set_max_retries(dns_max_retries_);
            LINOH_INFO("Builder: applied DNS fallback config, servers=", dns_fallback_servers_.size());
        }
    }

    return Endpoint::make(ctx, std::move(cfg_));
}

} // namespace linoh::endpoint
