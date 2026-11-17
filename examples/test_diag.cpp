#include "linoh/protocol/packet.hpp"
#include <iostream>
#include <vector>
#include <cstdio>

using namespace linoh::protocol;

int main() {
    // 模拟客户端发送的 1-RTT 包
    std::vector<uint8_t> dcid_bytes = {0x1f, 0xee, 0x32, 0xf6, 0x50, 0xca, 0x0c, 0x1c};
    ConnectionId dcid(std::span<const uint8_t>(dcid_bytes.data(), dcid_bytes.size()));

    // 构造 payload (STREAM frame for "Hello linoh!")
    std::vector<uint8_t> payload;
    payload.push_back(0x08 | 0x02);  // STREAM with 2-byte length
    payload.push_back(0);  // stream_id
    payload.push_back(0);  // len hi
    payload.push_back(12); // len lo
    std::string msg = "Hello linoh!";
    payload.insert(payload.end(), msg.begin(), msg.end());

    // 构造 1-RTT 包
    auto pkt_hdr = PacketHeader::make_1rtt(dcid);
    std::size_t hdr_size = pkt_hdr.encoded_size();
    std::vector<uint8_t> pkt(hdr_size + payload.size() + 8);
    std::size_t actual_hdr = pkt_hdr.serialize_to(pkt.data(), pkt.size());
    for (size_t i = 0; i < payload.size(); i++)
        pkt[actual_hdr + i] = payload[i];
    pkt.resize(actual_hdr + payload.size());

    std::cout << "Total packet size: " << pkt.size() << std::endl;
    std::cout << "First byte: 0x" << std::hex << (int)pkt[0] << std::dec << std::endl;
    std::cout << "Bytes: ";
    for (size_t i = 0; i < std::min((size_t)20, pkt.size()); i++)
        printf("%02x ", pkt[i]);
    printf("\n");

    // 尝试解析
    PacketParser parser(std::span<const uint8_t>(pkt.data(), pkt.size()));
    auto result = parser.parse();
    if (!result) {
        std::cout << "FAILED to parse 1-RTT packet!" << std::endl;
        return 1;
    }
    auto &parsed = *result;
    std::cout << "Parsed type: " << (int)parsed.header.type() << std::endl;
    std::cout << "Parsed dcid: " << parsed.header.dcid().fmt_short() << std::endl;
    std::cout << "Parsed payload size: " << parsed.payload.size() << std::endl;
    std::cout << "Payload bytes: ";
    auto ps = parsed.payload.as_span();
    for (size_t i = 0; i < std::min((size_t)10, ps.size()); i++)
        printf("%02x ", ps[i]);
    printf("\n");

    // 检查 Frame 解析
    auto frames = PacketParser::parse_frames(ps);
    std::cout << "Frames count: " << frames.size() << std::endl;
    for (size_t i = 0; i < frames.size(); i++) {
        std::cout << "  Frame " << i << ": type=" << (int)frames[i].type
                  << ", data_size=" << frames[i].data.size() << std::endl;
        if (!frames[i].data.empty()) {
            std::string text(frames[i].data.begin() + 1, frames[i].data.end());
            std::cout << "    Content: " << text << std::endl;
        }
    }

    // 现在测试 Initial 包解析
    std::vector<uint8_t> scid_bytes = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22};
    ConnectionId scid(std::span<const uint8_t>(scid_bytes.data(), scid_bytes.size()));
    auto init_hdr = PacketHeader::make_initial(dcid, scid);
    std::size_t init_hdr_size = init_hdr.encoded_size();
    std::vector<uint8_t> init_pkt(init_hdr_size + 4);
    std::size_t init_actual_hdr = init_hdr.serialize_to(init_pkt.data(), init_pkt.size());
    init_pkt[init_actual_hdr] = 0x00;  // PADDING
    init_pkt.resize(init_actual_hdr + 4);
    std::cout << "\nInitial packet: ";
    for (size_t i = 0; i < std::min((size_t)25, init_pkt.size()); i++)
        printf("%02x ", init_pkt[i]);
    printf("\n");

    PacketParser init_parser(std::span<const uint8_t>(init_pkt.data(), init_pkt.size()));
    auto init_result = init_parser.parse();
    if (init_result) {
        std::cout << "Initial parsed dcid: " << init_result->header.dcid().fmt_short() << std::endl;
    } else {
        std::cout << "Initial parse FAILED!" << std::endl;
    }

    return 0;
}
