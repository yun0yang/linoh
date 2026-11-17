#pragma once

/// @file result.hpp
/// 统一错误处理：Result<T, ErrorCode> 模式。
///
/// 用法：
///   auto r = connection.open_stream();
///   if (r.is_ok()) {
///       auto& stream = r.value();
///   } else {
///       auto error = r.error();
///   }

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

namespace linoh::util {

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// 连接层错误。
enum class ConnectionError : std::uint16_t {
    NoError            = 0,
    InternalError      = 1,
    ConnectionRefused  = 2,
    FlowControlError   = 3,
    StreamLimitError   = 4,
    StreamStateError   = 5,
    FinalSizeError     = 6,
    FrameEncodingError = 7,
    TransportError     = 8,
    CryptoError        = 9,
    IdleTimeout        = 10,
    HandshakeFailed    = 11,
    PathValidationFailed = 12,
};

/// Stream 层错误。
enum class StreamError : std::uint16_t {
    NoError           = 0,
    StreamClosed      = 1,
    InvalidOffset     = 2,
    FlowControlError  = 3,
    StreamReset       = 4,
    NoStreamAvailable = 5,
};

/// 协议层错误。
enum class ProtocolError : std::uint16_t {
    NoError              = 0,
    InvalidFrame         = 1,
    InvalidPacket        = 2,
    VersionNegotiation   = 3,
    UnexpectedFrame      = 4,
    FrameParsingFailed   = 5,
    VarIntOverflow       = 6,
    InvalidState         = 7,
    HandshakeTimeout     = 8,
};

/// 密码学错误。
enum class CryptoError : std::uint16_t {
    NoError           = 0,
    DecryptionFailed  = 1,
    EncryptionFailed  = 2,
    InvalidSignature  = 3,
    InvalidKey        = 4,
    RandomGenFailed   = 5,
};

/// 统一错误码（可以是任何 Error enum）。
struct ErrorCode {
    std::uint16_t code{0};
    std::string message;
    // 允许从任何 Error enum 构造
    ErrorCode() = default;
    ErrorCode(ConnectionError e, std::string msg = "")
        : code(static_cast<std::uint16_t>(e)), message(std::move(msg)) {}
    ErrorCode(StreamError e, std::string msg = "")
        : code(static_cast<std::uint16_t>(e)), message(std::move(msg)) {}
    ErrorCode(ProtocolError e, std::string msg = "")
        : code(static_cast<std::uint16_t>(e)), message(std::move(msg)) {}
    ErrorCode(CryptoError e, std::string msg = "")
        : code(static_cast<std::uint16_t>(e)), message(std::move(msg)) {}

    bool is_ok() const { return code == 0; }
    std::uint16_t value() const { return code; }
    const std::string &msg() const { return message; }
};

// ---------------------------------------------------------------------------
// Result<T, ErrorCode>
// ---------------------------------------------------------------------------

/// Result<T, ErrorCode> — 成功返回 T，失败返回 ErrorCode。
template<typename T>
class Result {
public:
    /// 成功构造。
    Result(T value) : data_(std::move(value)) {}

    /// 失败构造。
    Result(ErrorCode error) : data_(error) {}

    /// 从 ConnectionError 构造失败结果。
    Result(ConnectionError e, std::string msg = "")
        : data_(ErrorCode(e, std::move(msg))) {}

    /// 从 StreamError 构造失败结果。
    Result(StreamError e, std::string msg = "")
        : data_(ErrorCode(e, std::move(msg))) {}

    /// 从 ProtocolError 构造失败结果。
    Result(ProtocolError e, std::string msg = "")
        : data_(ErrorCode(e, std::move(msg))) {}

    /// 从 CryptoError 构造失败结果。
    Result(CryptoError e, std::string msg = "")
        : data_(ErrorCode(e, std::move(msg))) {}

    bool is_ok() const { return std::holds_alternative<T>(data_); }
    bool is_err() const { return std::holds_alternative<ErrorCode>(data_); }

    /// 获取值（仅在 is_ok() 时有效）。
    T &value() { return std::get<T>(data_); }
    const T &value() const { return std::get<T>(data_); }

    /// 获取错误码（仅在 is_err() 时有效）。
    ErrorCode &error() { return std::get<ErrorCode>(data_); }
    const ErrorCode &error() const { return std::get<ErrorCode>(data_); }

    /// 获取值或默认值。
    T value_or(T default_val) const {
        if (is_ok()) return std::get<T>(data_);
        return std::move(default_val);
    }

private:
    std::variant<T, ErrorCode> data_;
};

/// Result<void, ErrorCode> — void 特化，仅表示成功或失败。
class ResultVoid {
public:
    ResultVoid() : error_(std::nullopt) {}
    ResultVoid(ErrorCode error) : error_(std::move(error)) {}

    ResultVoid(ConnectionError e, std::string msg = "")
        : error_(ErrorCode(e, std::move(msg))) {}
    ResultVoid(StreamError e, std::string msg = "")
        : error_(ErrorCode(e, std::move(msg))) {}
    ResultVoid(ProtocolError e, std::string msg = "")
        : error_(ErrorCode(e, std::move(msg))) {}
    ResultVoid(CryptoError e, std::string msg = "")
        : error_(ErrorCode(e, std::move(msg))) {}

    bool is_ok() const { return !error_.has_value(); }
    bool is_err() const { return error_.has_value(); }

    ErrorCode &error() { return *error_; }
    const ErrorCode &error() const { return *error_; }

private:
    std::optional<ErrorCode> error_;
};

} // namespace linoh::util
