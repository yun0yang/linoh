// packet_builder.cpp — P4-D-1 PacketBuilder 实现
//
// 委托回 Connection 的对应方法，后续可逐步把实现迁移到此文件。

#include "linoh/endpoint/connection_internal.hpp"

namespace linoh::endpoint::internal {

std::size_t PacketBuilder::build_1rtt_packet(std::span<std::uint8_t> out) {
    return conn_->build_1rtt_packet(out);
}

std::size_t PacketBuilder::build_0rtt_packet(std::span<std::uint8_t> out) {
    return conn_->build_0rtt_packet(out);
}

std::vector<std::uint8_t> PacketBuilder::build_ack_data() {
    return conn_->build_ack_data();
}

util::Bytes PacketBuilder::encrypt_packet(std::span<const std::uint8_t> header,
                                            std::span<const std::uint8_t> payload) {
    return conn_->encrypt_packet(header, payload);
}

std::optional<util::Bytes> PacketBuilder::decrypt_packet(
    std::span<const std::uint8_t> header,
    std::span<const std::uint8_t> cipher) {
    return conn_->decrypt_packet(header, cipher);
}

void PacketBuilder::update_rtt(double rtt_ms) {
    conn_->update_rtt(rtt_ms);
}

void PacketBuilder::handle_ack_frame(const protocol::AckFrame &ack) {
    conn_->handle_ack_frame(ack);
}

std::vector<std::uint64_t> PacketBuilder::pending_retransmits() const {
    return conn_->pending_retransmits();
}

} // namespace linoh::endpoint::internal
