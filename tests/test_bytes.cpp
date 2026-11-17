#include "linoh/util/bytes.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

using namespace linoh::util;

int main() {
    // 1. 基础构造 + size/data
    std::string msg = "hello bytes";
    Bytes b{std::string_view(msg)};
    assert(b.size() == msg.size());
    assert(std::memcmp(b.data(), msg.data(), msg.size()) == 0);

    // 2. slice: 子视图
    Bytes sub = b.slice(6, 5);
    assert(sub.size() == 5);
    assert(std::memcmp(sub.data(), "bytes", 5) == 0);

    // 3. slice 共享存储: 深拷贝可验证
    Bytes c = b.copy();
    assert(c == b);
    Bytes d{std::string_view("different")};
    assert(!(d == b));

    // 4. allocate 验证 size
    Bytes e = Bytes::allocate(16);
    assert(e.size() == 16);

    // 5. MutableBytes: 分配 -> 写入 -> freeze
    MutableBytes mb(64);
    assert(mb.size() == 64);
    std::string text = "mutable hello";
    std::memcpy(mb.data(), text.data(), text.size());
    Bytes frozen = mb.freeze(text.size());
    assert(frozen.size() == text.size());
    assert(std::memcmp(frozen.data(), text.data(), text.size()) == 0);

    // 6. 空的 Bytes
    Bytes empty;
    assert(empty.size() == 0);
    assert(empty.data() == nullptr);

    // 7. as_string_view
    Bytes sv{std::string_view("abcdef")};
    assert(sv.as_string_view() == "abcdef");

    std::cout << "[OK] test_bytes passed\n";
    return 0;
}
