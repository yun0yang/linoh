// linoh/net/bidirectional_holepuncher.cpp
//
// v5.0.0 (T-LP4-004): Hard-NAT 双向端口预测 + 多轮打洞协调器实现

#include "linoh/net/bidirectional_holepuncher.hpp"
#include "linoh/util/logging.hpp"

#include <algorithm>
#include <sstream>

namespace linoh::net {

// ============================================================================
// HolepunchRound
// ============================================================================

std::string HolepunchRound::to_string() const {
    std::ostringstream oss;
    oss << "Round#" << round_id << " status=";
    switch (status) {
    case RoundStatus::Active:    oss << "Active"; break;
    case RoundStatus::Aborted:   oss << "Aborted"; break;
    case RoundStatus::Succeeded: oss << "Succeeded"; break;
    case RoundStatus::Failed:    oss << "Failed"; break;
    }
    oss << " candidates=" << candidate_ports.size()
        << " sent=" << sent_challenge_ports.size()
        << " responded=" << responded_ports.size()
        << " duration=" << duration().count() << "ms";
    if (!relay_observed_host.empty()) {
        oss << " relay_obs=" << relay_observed_host << ":" << relay_observed_port;
    }
    return oss.str();
}

// ============================================================================
// BidirectionalHolepuncher
// ============================================================================

std::uint32_t BidirectionalHolepuncher::start_round(
    std::vector<std::uint16_t> candidate_ports,
    std::vector<std::uint16_t> predicted_remote,
    std::vector<std::uint16_t> predicted_local) {
    std::lock_guard<std::mutex> lk(mu_);

    // 中止当前活跃轮次（如果有）
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            r.status = RoundStatus::Aborted;
            r.end_time = std::chrono::steady_clock::now();
            LINOH_INFO("BidirHolepunch: round#", r.round_id,
                       " aborted (new round started)");
        }
    }

    // 创建新轮次
    HolepunchRound round;
    round.round_id = next_round_id_++;
    round.status = RoundStatus::Active;
    round.start_time = std::chrono::steady_clock::now();
    round.candidate_ports = std::move(candidate_ports);
    round.predicted_remote_ports = std::move(predicted_remote);
    round.predicted_local_ports = std::move(predicted_local);

    rounds_.push_back(std::move(round));

    prune_history_locked();

    LINOH_INFO("BidirHolepunch: started round#", rounds_.back().round_id,
               " candidates=", rounds_.back().candidate_ports.size());

    return rounds_.back().round_id;
}

void BidirectionalHolepuncher::abort_current_round() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            r.status = RoundStatus::Aborted;
            r.end_time = std::chrono::steady_clock::now();
            LINOH_INFO("BidirHolepunch: round#", r.round_id, " aborted");
        }
    }
}

void BidirectionalHolepuncher::mark_succeeded(std::uint16_t established_port) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            r.status = RoundStatus::Succeeded;
            r.end_time = std::chrono::steady_clock::now();
            r.responded_ports.push_back(established_port);
            successful_round_id_ = r.round_id;
            LINOH_INFO("BidirHolepunch: round#", r.round_id,
                       " SUCCEEDED on port=", established_port);
            return;
        }
    }
    LINOH_WARN("BidirHolepunch: mark_succeeded called but no active round");
}

void BidirectionalHolepuncher::mark_failed() {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            r.status = RoundStatus::Failed;
            r.end_time = std::chrono::steady_clock::now();
            LINOH_INFO("BidirHolepunch: round#", r.round_id, " FAILED");
            return;
        }
    }
}

bool BidirectionalHolepuncher::check_timeout(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lk(mu_);
    bool any_timed_out = false;
    auto now = std::chrono::steady_clock::now();
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - r.start_time);
            if (elapsed > timeout) {
                r.status = RoundStatus::Failed;
                r.end_time = now;
                any_timed_out = true;
                LINOH_INFO("BidirHolepunch: round#", r.round_id,
                           " timed out (", elapsed.count(), "ms > ",
                           timeout.count(), "ms)");
            }
        }
    }
    return any_timed_out;
}

bool BidirectionalHolepuncher::record_challenge_sent(std::uint16_t port) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            // 检查是否已发送过
            if (std::find(r.sent_challenge_ports.begin(),
                          r.sent_challenge_ports.end(),
                          port) != r.sent_challenge_ports.end()) {
                return false;  // 已发送过，跳过
            }
            r.sent_challenge_ports.push_back(port);
            return true;
        }
    }
    return false;  // 无活跃轮次
}

bool BidirectionalHolepuncher::record_response(std::uint16_t port) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            // 检查是否匹配已发送的 CHALLENGE
            auto it = std::find(r.sent_challenge_ports.begin(),
                                r.sent_challenge_ports.end(),
                                port);
            if (it != r.sent_challenge_ports.end()) {
                r.responded_ports.push_back(port);
                LINOH_DEBUG("BidirHolepunch: PATH_RESPONSE matched on port=", port,
                            " round#", r.round_id);
                return true;
            }
        }
    }
    return false;
}

void BidirectionalHolepuncher::update_relay_observed_addr(
    const std::string &host, std::uint16_t port) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            r.relay_observed_host = host;
            r.relay_observed_port = port;
            LINOH_INFO("BidirHolepunch: relay observed addr=", host, ":", port,
                       " round#", r.round_id);
            return;
        }
    }
}

std::optional<HolepunchRound> BidirectionalHolepuncher::current_round() const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &r : rounds_) {
        if (r.status == RoundStatus::Active) {
            return r;
        }
    }
    return std::nullopt;
}

bool BidirectionalHolepuncher::is_active() const {
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto &r : rounds_) {
        if (r.status == RoundStatus::Active) return true;
    }
    return false;
}

std::vector<HolepunchRound> BidirectionalHolepuncher::history_rounds() const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<HolepunchRound> history;
    for (const auto &r : rounds_) {
        if (r.status != RoundStatus::Active) {
            history.push_back(r);
        }
    }
    return history;
}

std::size_t BidirectionalHolepuncher::total_rounds() const {
    std::lock_guard<std::mutex> lk(mu_);
    return rounds_.size();
}

std::optional<HolepunchRound> BidirectionalHolepuncher::successful_round() const {
    std::lock_guard<std::mutex> lk(mu_);
    if (!successful_round_id_) return std::nullopt;
    for (const auto &r : rounds_) {
        if (r.round_id == *successful_round_id_) {
            return r;
        }
    }
    return std::nullopt;
}

std::pair<std::vector<std::uint16_t>, std::vector<std::uint16_t>>
BidirectionalHolepuncher::predict_bidirectional_ports(
    std::uint16_t local_observed_port_1,
    std::uint16_t local_observed_port_2,
    std::uint16_t remote_observed_port_1,
    std::uint16_t remote_observed_port_2,
    std::size_t predictions_count) {
    // 双向预测：本端预测对端端口 + 对端预测本端端口
    auto predicted_remote = predict_symmetric_nat_ports(
        remote_observed_port_1, remote_observed_port_2, predictions_count);
    auto predicted_local = predict_symmetric_nat_ports(
        local_observed_port_1, local_observed_port_2, predictions_count);
    return {predicted_remote, predicted_local};
}

void BidirectionalHolepuncher::prune_history_locked() {
    // 保留活跃轮次 + 最近 kMaxHistoryRounds 个历史轮次
    std::size_t active_count = 0;
    for (const auto &r : rounds_) {
        if (r.status == RoundStatus::Active) ++active_count;
    }

    std::size_t history_count = rounds_.size() - active_count;
    if (history_count <= kMaxHistoryRounds) return;

    // 需要删除的历史轮次数量
    std::size_t to_remove = history_count - kMaxHistoryRounds;

    // 从前面开始删除（最旧的），但保留活跃轮次
    auto it = rounds_.begin();
    while (it != rounds_.end() && to_remove > 0) {
        if (it->status != RoundStatus::Active) {
            it = rounds_.erase(it);
            --to_remove;
        } else {
            ++it;
        }
    }
}

} // namespace linoh::net
