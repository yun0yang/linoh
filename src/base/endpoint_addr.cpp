#include "linoh/base/endpoint_addr.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <sstream>
#include <string>

namespace linoh::base {

namespace {

/// 解析 scheme://host[:port]/path 风格 URL —— 足够覆盖 iroh relay URL 场景。
void parse_url(const std::string &url, std::string &scheme, std::string &host, uint16_t &port) {
    auto pos = url.find("://");
    if (pos == std::string::npos) {
        scheme = "https";
        host = url;
        port = 443;
        return;
    }
    scheme = url.substr(0, pos);
    std::string rest = url.substr(pos + 3);
    // 去掉尾部路径
    auto slash = rest.find('/');
    if (slash != std::string::npos) rest = rest.substr(0, slash);
    // IPv6 host 用 [] 括起
    if (!rest.empty() && rest.front() == '[') {
        auto end = rest.find(']');
        if (end != std::string::npos) {
            host = rest.substr(1, end - 1);
            if (end + 1 < rest.size() && rest[end + 1] == ':') {
                port = static_cast<uint16_t>(std::stoi(rest.substr(end + 2)));
            } else {
                port = (scheme == "https") ? 443 : 80;
            }
            return;
        }
    }
    auto colon = rest.find(':');
    if (colon != std::string::npos) {
        host = rest.substr(0, colon);
        port = static_cast<uint16_t>(std::stoi(rest.substr(colon + 1)));
    } else {
        host = rest;
        port = (scheme == "https") ? 443 : 80;
    }
}

} // namespace

RelayUrl::RelayUrl(std::string url) : url_{std::move(url)} {
    parse_url(url_, scheme_, host_, port_);
}

} // namespace linoh::base
