// stream_manager.cpp — P4-D-1 StreamManager 实现
//
// 委托回 Connection 的对应方法，后续可逐步把实现迁移到此文件。

#include "linoh/endpoint/connection_internal.hpp"

namespace linoh::endpoint::internal {

std::shared_ptr<Stream> StreamManager::open_stream() {
    return conn_->open_stream();
}

util::Result<std::shared_ptr<Stream>> StreamManager::try_open_stream() {
    return conn_->try_open_stream();
}

util::Result<std::shared_ptr<Stream>> StreamManager::try_accept_stream() {
    return conn_->try_accept_stream();
}

std::shared_ptr<Stream> StreamManager::accept_stream() {
    return conn_->accept_stream();
}

void StreamManager::send_stream(std::uint64_t stream_id, std::span<const std::uint8_t> data) {
    conn_->send_stream(stream_id, data);
}

void StreamManager::finish_stream(std::uint64_t stream_id) {
    conn_->finish_stream(stream_id);
}

std::uint64_t StreamManager::next_local_stream_id(bool bidi) {
    return conn_->next_local_stream_id(bidi);
}

void StreamManager::on_stream(std::function<void(std::shared_ptr<Stream>)> h) {
    conn_->on_stream(std::move(h));
}

std::mutex &StreamManager::stream_mutex() {
    return conn_->stream_mutex();
}

std::shared_ptr<Stream> StreamManager::acquire_rpc_stream() {
    return conn_->acquire_rpc_stream();
}

void StreamManager::release_rpc_stream(std::shared_ptr<Stream> stream) {
    conn_->release_rpc_stream(std::move(stream));
}

void StreamManager::register_request_stream(std::uint32_t request_id,
                                              std::shared_ptr<Stream> stream) {
    conn_->register_request_stream(request_id, std::move(stream));
}

std::shared_ptr<Stream> StreamManager::take_request_stream(std::uint32_t request_id) {
    return conn_->take_request_stream(request_id);
}

std::size_t StreamManager::rpc_stream_pool_size() const {
    return conn_->rpc_stream_pool_size();
}

std::size_t StreamManager::rpc_in_flight_count() const {
    return conn_->rpc_in_flight_count();
}

} // namespace linoh::endpoint::internal
