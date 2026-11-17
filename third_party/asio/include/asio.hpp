// asio.hpp - Minimal stub compatible with linoh's usage patterns.
// For real networking, install full Asio from https://think-async.com/Asio/
#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <system_error>
#include <vector>

namespace linoh_asio {

    using error_code = std::error_code;
    inline const std::error_category& system_category() noexcept { return std::system_category(); }
    inline const std::error_category& generic_category() noexcept { return std::system_category(); }

    class io_context;

    // --- Error codes ------------------------------------------------------
    // 使用 std::errc 的整数值，确保 make_error_code 后与 stub 内部产生的
    // std::error_code(std::errc::operation_canceled, std::generic_category()) 完全相等。
    namespace error {
        enum error_t {
            operation_aborted = static_cast<int>(std::errc::operation_canceled),
            eof = static_cast<int>(std::errc::io_error),
            connection_reset = static_cast<int>(std::errc::connection_reset),
        };

        // ADL 查找：必须与 error_t 在同一命名空间，std::error_code 构造时才能找到
        inline std::error_code make_error_code(error_t e) noexcept {
            return std::error_code(static_cast<int>(e), std::generic_category());
        }
    } // namespace error

} // namespace linoh_asio

namespace std {
    template <>
    struct is_error_code_enum<linoh_asio::error::error_t> : true_type {};
} // namespace std

namespace linoh_asio {

    // --- Buffer helpers ---------------------------------------------------
    struct const_buffer {
        const void* data_ = nullptr;
        std::size_t size_ = 0;
        const_buffer() = default;
        const_buffer(const void* d, std::size_t s) : data_(d), size_(s) {}
        const void* data() const { return data_; }
        std::size_t size() const { return size_; }
    };
    struct mutable_buffer {
        void* data_ = nullptr;
        std::size_t size_ = 0;
        mutable_buffer() = default;
        mutable_buffer(void* d, std::size_t s) : data_(d), size_(s) {}
        void* data() const { return data_; }
        std::size_t size() const { return size_; }
    };
    inline const_buffer buffer(const void* d, std::size_t s) { return const_buffer(d, s); }
    inline mutable_buffer buffer(void* d, std::size_t s) { return mutable_buffer(d, s); }
    inline const_buffer buffer(const std::vector<unsigned char>& v) { return const_buffer(v.data(), v.size()); }
    inline mutable_buffer buffer(std::vector<unsigned char>& v) { return mutable_buffer(v.data(), v.size()); }
    inline const_buffer buffer(const std::vector<char>& v) { return const_buffer(v.data(), v.size()); }
    inline mutable_buffer buffer(std::vector<char>& v) { return mutable_buffer(v.data(), v.size()); }
    // String buffer support (needed for WebSocket handshake)
    inline const_buffer buffer(const std::string& s) { return const_buffer(s.data(), s.size()); }
    inline mutable_buffer buffer(std::string& s) { return mutable_buffer(s.data(), s.size()); }

    // --- IP layer ---------------------------------------------------------
    namespace ip {

    // v6_only socket option must be defined BEFORE udp namespace
    struct v6_only {
        int value_;
        v6_only() : value_(0) {}
        explicit v6_only(int v) : value_(v) {}
        operator int() const { return value_; }
    };

    struct protocol {
        int version = 4;
    };
    inline protocol v4() { return protocol{4}; }
    inline protocol v6() { return protocol{6}; }

    class address {
    public:
        address() = default;
        static address from_string(const std::string&) { return address{}; }
        std::string to_string() const { return "127.0.0.1"; }
        bool is_loopback() const { return true; }
        bool is_v4() const { return true; }
        bool is_v6() const { return false; }
        static address any() { return address{}; }
        static address loopback() { return address{}; }
    };

    // Stub endpoint
    class endpoint {
    public:
        endpoint() : port_(0) {}
        endpoint(const address&, std::uint16_t p) : port_(p) {}
        template <typename Family>
        endpoint(const Family&, std::uint16_t p) : port_(p) {}

        address addr() const { address a; return a; }
        address address_() const { address a; return a; }
        std::uint16_t port() const { return port_; }
        void port(std::uint16_t p) { port_ = p; }

    private:
        std::uint16_t port_;
    };

    // --- UDP --------------------------------------------------------------
    namespace udp {
        using endpoint = ::linoh_asio::ip::endpoint;
        using protocol = ::linoh_asio::ip::protocol;
        inline protocol v4() { return ::linoh_asio::ip::v4(); }
        inline protocol v6() { return ::linoh_asio::ip::v6(); }

        class resolver {
        public:
            resolver() = default;
            explicit resolver(::linoh_asio::io_context&) {}

            struct iterator {
                endpoint ep_;
                bool valid_ = true;
                iterator() {}
                iterator(const endpoint& e) : ep_(e) {}
                // 模拟真实 asio 的 basic_resolver_entry，提供 .endpoint() 方法
                // 修复（2026-07-17）：g++ 下 entry::endpoint() 会被解析为类型名而非方法名
                // 使用全限定类型 ::linoh_asio::ip::endpoint 避免歧义
                struct entry {
                    ::linoh_asio::ip::endpoint ep_;
                    const ::linoh_asio::ip::endpoint& endpoint() const { return ep_; }
                    operator const ::linoh_asio::ip::endpoint&() const { return ep_; }
                };
                entry operator*() const { return entry{ep_}; }
                const endpoint* operator->() const { return &ep_; }
                iterator& operator++() { valid_ = false; return *this; }
                bool operator!=(const iterator& o) const { return valid_ != o.valid_; }
                bool operator==(const iterator& o) const { return valid_ == o.valid_; }
            };

            struct results_type {
                endpoint ep_;
                results_type() {}
                explicit results_type(const endpoint& e) : ep_(e) {}
                iterator begin() const { return iterator(ep_); }
                iterator end() const { iterator it; it.valid_ = false; return it; }
            };

            results_type resolve(const protocol&, const std::string&, const std::string&) { return results_type{}; }
            results_type resolve(const std::string&, const std::string&) { return results_type{}; }
        };

        class socket {
        public:
            socket() = default;
            explicit socket(::linoh_asio::io_context&) {}
            void open(int) {}
            void open(const protocol&) {}
            void set_option(const ::linoh_asio::ip::v6_only&, int = 0) {}
            void set_option(int, int) {}
            void bind(const endpoint&) {}

            template <typename ConstBufSeq>
            std::size_t send_to(const ConstBufSeq& buf, const endpoint& ep, int = 0) {
                (void)buf; (void)ep; return 0;
            }

            template <typename MutableBufSeq, typename Handler>
            void async_receive_from(const MutableBufSeq&, endpoint&, Handler&& h) {
                h(std::error_code(static_cast<int>(std::errc::operation_canceled),
                                   std::generic_category()),
                  static_cast<std::size_t>(0));
            }

            template <typename MutableBufSeq>
            std::size_t receive_from(const MutableBufSeq&, endpoint&, int = 0,
                                      std::error_code* ec = nullptr) {
                if (ec) *ec = std::error_code(static_cast<int>(std::errc::not_connected),
                                                std::generic_category());
                return 0;
            }

            template <typename ConstBufSeq>
            std::size_t send(const ConstBufSeq&, int = 0) { return 0; }
            template <typename ConstBufSeq>
            std::size_t write_some(const ConstBufSeq&, int = 0) { return 0; }
            template <typename MutableBufSeq>
            std::size_t read_some(const MutableBufSeq&, int = 0) { return 0; }

            template <typename MutableBufSeq, typename Handler>
            void async_read_some(const MutableBufSeq&, Handler&& h) {
                h(std::error_code(static_cast<int>(std::errc::operation_canceled),
                                   std::generic_category()),
                  static_cast<std::size_t>(0));
            }
            template <typename ConstBufSeq, typename Handler>
            void async_write_some(const ConstBufSeq&, Handler&& h) {
                h(std::error_code(), static_cast<std::size_t>(0));
            }

            void close() {}
            void close(std::error_code) {}
            void cancel() {}
            bool is_open() const { return true; }
            endpoint local_endpoint() const { return endpoint{}; }
        };
    } // namespace udp

    // --- TCP --------------------------------------------------------------
    namespace tcp {
        using endpoint = ::linoh_asio::ip::endpoint;
        using protocol = ::linoh_asio::ip::protocol;

        class resolver {
        public:
            resolver() = default;
            explicit resolver(::linoh_asio::io_context&) {}

            struct iterator {
                endpoint ep_;
                bool valid_ = true;
                iterator() {}
                iterator(const endpoint& e) : ep_(e) {}
                // 模拟真实 asio 的 basic_resolver_entry，提供 .endpoint() 方法
                // 修复（2026-07-17）：g++ 下 entry::endpoint() 会被解析为类型名而非方法名
                // 使用全限定类型 ::linoh_asio::ip::endpoint 避免歧义
                struct entry {
                    ::linoh_asio::ip::endpoint ep_;
                    const ::linoh_asio::ip::endpoint& endpoint() const { return ep_; }
                    operator const ::linoh_asio::ip::endpoint&() const { return ep_; }
                };
                entry operator*() const { return entry{ep_}; }
                const endpoint* operator->() const { return &ep_; }
                iterator& operator++() { valid_ = false; return *this; }
                bool operator!=(const iterator& o) const { return valid_ != o.valid_; }
                bool operator==(const iterator& o) const { return valid_ == o.valid_; }
            };

            struct results_type {
                endpoint ep_;
                results_type() {}
                explicit results_type(const endpoint& e) : ep_(e) {}
                iterator begin() const { return iterator(ep_); }
                iterator end() const { iterator it; it.valid_ = false; return it; }
            };

            results_type resolve(const protocol&, const std::string&, const std::string&) { return results_type{}; }
            results_type resolve(const std::string&, const std::string&) { return results_type{}; }
        };

        class socket {
        public:
            socket() = default;
            explicit socket(::linoh_asio::io_context&) {}
            void open(int) {}
            void open(const protocol&) {}
            void set_option(int, int) {}
            void bind(const endpoint&) {}
            void connect(const endpoint&) {}
            void close() {}
            void close(std::error_code) {}
            void cancel() {}
            bool is_open() const { return true; }
            endpoint local_endpoint() const { return endpoint{}; }
            endpoint remote_endpoint() const { return endpoint{}; }

            template <typename ConstBufSeq>
            std::size_t send(const ConstBufSeq&, int = 0) { return 0; }
            template <typename ConstBufSeq>
            std::size_t write_some(const ConstBufSeq&, int = 0) { return 0; }
            template <typename MutableBufSeq>
            std::size_t read_some(const MutableBufSeq&, int = 0) { return 0; }
            template <typename MutableBufSeq>
            std::size_t read_some(const MutableBufSeq&, std::error_code& ec) {
                ec = std::error_code(); return 0;
            }

            template <typename MutableBufSeq, typename Handler>
            void async_read_some(const MutableBufSeq&, Handler&& h) {
                h(std::error_code(static_cast<int>(std::errc::operation_canceled),
                                   std::generic_category()),
                  static_cast<std::size_t>(0));
            }
            template <typename ConstBufSeq, typename Handler>
            void async_write_some(const ConstBufSeq&, Handler&& h) {
                h(std::error_code(), static_cast<std::size_t>(0));
            }
        };
    } // namespace tcp

    } // namespace ip

    // --- Free functions ---------------------------------------------------
    template <typename AsyncStream, typename MutableBufSeq, typename Handler>
    inline void async_read(AsyncStream&, const MutableBufSeq&, Handler&& h) {
        h(std::error_code(static_cast<int>(std::errc::operation_canceled),
                           std::generic_category()),
          static_cast<std::size_t>(0));
    }

    template <typename SyncStream, typename ConstBufSeq>
    inline std::size_t write(SyncStream&, const ConstBufSeq&, std::error_code& ec) {
        ec = std::error_code();
        return 0;
    }

    template <typename SyncStream, typename ConstBufSeq>
    inline std::size_t write(SyncStream&, const ConstBufSeq&) { return 0; }

    template <typename SyncStream, typename EndpointIterator>
    inline EndpointIterator connect(SyncStream&, EndpointIterator begin) {
        return begin;
    }

    // --- Timer & io_context stubs ----------------------------------------
    class deadline_timer {
    public:
        deadline_timer() = default;
        explicit deadline_timer(void*) {}
        void expires_at(void*) {}
        void async_wait(std::function<void(const error_code&)>) {}
        void cancel() {}
    };

    class steady_timer {
    public:
        steady_timer() = default;
        explicit steady_timer(void*) {}
        explicit steady_timer(::linoh_asio::io_context&) {}
        steady_timer(::linoh_asio::io_context&, int /*duration_seconds*/) {}
        template <typename Rep, typename Period>
        steady_timer(::linoh_asio::io_context&, const std::chrono::duration<Rep, Period>&) {}
        void expires_at(void*) {}
        void expires_after(int) {}
        template <typename Rep, typename Period>
        void expires_after(const std::chrono::duration<Rep, Period>&) {}
        void async_wait(std::function<void(const error_code&)>) {}
        void cancel() {}
    };

    class io_context {
    public:
        io_context() = default;
        void run() {}
        void stop() {}
        bool stopped() const { return false; }
        void reset() {}
        void notify_fork(int) {}
    };

} // namespace linoh_asio

namespace asio { using namespace linoh_asio; }
