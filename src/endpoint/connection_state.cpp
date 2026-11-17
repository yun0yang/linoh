// connection_state.cpp — P4-D-1 ConnectionState 实现
//
// 委托回 Connection 的对应方法，后续可逐步把实现迁移到此文件。

#include "linoh/endpoint/connection_internal.hpp"

namespace linoh::endpoint::internal {

ConnState ConnectionState::state() const {
    return conn_->state();
}

bool ConnectionState::is_closed() const {
    return conn_->is_closed();
}

void ConnectionState::transition_to(ConnState new_state) {
    conn_->state_.store(new_state);
}

bool ConnectionState::tls13_enabled() const {
    return conn_->tls13_enabled();
}

bool ConnectionState::tls13_active() const {
    return conn_->tls13_active();
}

util::ResultVoid ConnectionState::start_handshake(double now_ms) {
    return conn_->start_handshake(now_ms);
}

bool ConnectionState::check_handshake_timeout(double now_ms) const {
    return conn_->check_handshake_timeout(now_ms);
}

std::vector<std::uint8_t> ConnectionState::take_handshake_flight() {
    return conn_->take_handshake_flight();
}

void ConnectionState::feed_handshake(std::span<const std::uint8_t> bytes) {
    conn_->feed_handshake(bytes);
}

void ConnectionState::on_handshake_completed() {
    conn_->on_handshake_completed();
}

void ConnectionState::finalize_tls13() {
    conn_->finalize_tls13();
}

void ConnectionState::force_psk_established() {
    conn_->force_psk_established();
}

std::optional<SessionTicket> ConnectionState::save_session() const {
    return conn_->save_session();
}

bool ConnectionState::is_resumed() const {
    return conn_->is_resumed();
}

void ConnectionState::queue_early_data(std::span<const std::uint8_t> data) {
    conn_->queue_early_data(data);
}

std::uint8_t ConnectionState::key_phase() const {
    return conn_->key_phase();
}

bool ConnectionState::trigger_key_update() {
    return conn_->trigger_key_update();
}

bool ConnectionState::should_rotate_keys() const {
    return conn_->should_rotate_keys();
}

std::uint64_t ConnectionState::packets_sent_since_rotate() const {
    return conn_->packets_sent_since_rotate();
}

bool ConnectionState::rotate_keys() {
    return conn_->rotate_keys();
}

void ConnectionState::close(std::uint16_t error_code, std::string reason, Connection::CloseMode mode) {
    conn_->close(error_code, std::move(reason), mode);
}

void ConnectionState::close_immediate(std::uint16_t error_code, std::string reason) {
    conn_->close_immediate(error_code, std::move(reason));
}

void ConnectionState::trigger_on_close_once() {
    conn_->trigger_on_close_once();
}

void ConnectionState::on_close_impl() {
    conn_->on_close_impl();
}

bool ConnectionState::check_idle_timeout(double now_ms) {
    return conn_->check_idle_timeout(now_ms);
}

bool ConnectionState::needs_keepalive(double now_ms) const {
    return conn_->needs_keepalive(now_ms);
}

void ConnectionState::record_activity(double now_ms) {
    conn_->record_activity(now_ms);
}

void ConnectionState::request_ping() {
    conn_->request_ping();
}

} // namespace linoh::endpoint::internal
