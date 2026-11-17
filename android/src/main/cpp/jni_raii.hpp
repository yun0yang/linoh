// jni_raii.hpp — linoh-android JNI RAII 工具类
//
// 提供 JNIEnv 自动附加、LocalRef/GlobalRef 自动释放、jstring 转换等工具，
// 避免手写 JNI 代码常见的资源泄漏和线程上下文错误。
//
// 设计原则：薄包装 + RAII，不引入第三方依赖。

#pragma once

#include <jni.h>
#include <memory>
#include <string>

namespace linoh::jni {

// ============================================================================
// JniEnvGuard：JNIEnv 线程附加守护
//
// 构造时若当前线程未附加到 JVM，则 AttachCurrentThread；
// 析构时若本对象触发了附加，则 DetachCurrentThread。
//
// 使用场景：linoh 内部线程触发回调时，需先获取 JNIEnv 才能调用 Kotlin 侧。
// ============================================================================
class JniEnvGuard {
public:
    explicit JniEnvGuard(JavaVM *vm);
    ~JniEnvGuard();

    JniEnvGuard(const JniEnvGuard &) = delete;
    JniEnvGuard &operator=(const JniEnvGuard &) = delete;

    JNIEnv *env() const { return env_; }
    bool attached() const { return attached_; }

private:
    JavaVM *vm_;
    JNIEnv *env_;
    bool attached_;  // 本对象是否触发了 Attach
};

// ============================================================================
// JniLocalRef：自动释放 LocalRef
//
// JNI LocalRef 在 frame 退出时自动释放，但显式管理可避免 table 溢出
// （长循环中频繁创建 LocalRef 会撑爆 Local Reference Table）。
// ============================================================================
template <typename T>
class JniLocalRef {
public:
    JniLocalRef(JNIEnv *env, T ref) : env_(env), ref_(ref) {}
    ~JniLocalRef() {
        if (ref_) env_->DeleteLocalRef(ref_);
    }
    JniLocalRef(const JniLocalRef &) = delete;
    JniLocalRef &operator=(const JniLocalRef &) = delete;

    T get() const { return ref_; }
    T release() { T t = ref_; ref_ = nullptr; return t; }
    explicit operator bool() const { return ref_ != nullptr; }

private:
    JNIEnv *env_;
    T ref_;
};

// ============================================================================
// JniGlobalRef：长期持有 GlobalRef
//
// 用于回调 Kotlin 函数式接口（Function1 等）时长期持有 jobject 引用。
// ============================================================================
template <typename T>
class JniGlobalRef {
public:
    JniGlobalRef() : env_(nullptr), ref_(nullptr) {}
    JniGlobalRef(JNIEnv *env, T ref) : env_(env), ref_(env->NewGlobalRef(ref)) {}
    ~JniGlobalRef() {
        if (ref_) {
            // env_ 可能在析构时已无效，需通过 JavaVM 重新获取
            // 简化处理：要求调用者保证析构时 JVM 仍可用
            env_->DeleteGlobalRef(ref_);
        }
    }
    JniGlobalRef(const JniGlobalRef &) = delete;
    JniGlobalRef &operator=(const JniGlobalRef &) = delete;

    JniGlobalRef(JniGlobalRef &&other) noexcept
        : env_(other.env_), ref_(other.ref_) {
        other.ref_ = nullptr;
    }
    JniGlobalRef &operator=(JniGlobalRef &&other) noexcept {
        if (this != &other) {
            if (ref_) env_->DeleteGlobalRef(ref_);
            env_ = other.env_;
            ref_ = other.ref_;
            other.ref_ = nullptr;
        }
        return *this;
    }

    T get() const { return ref_; }
    explicit operator bool() const { return ref_ != nullptr; }

private:
    JNIEnv *env_;
    T ref_;
};

// ============================================================================
// jstring <-> std::string 转换
// ============================================================================
std::string jstring_to_utf8(JNIEnv *env, jstring jstr);
jstring utf8_to_jstring(JNIEnv *env, const std::string &str);

// ============================================================================
// 异常辅助：把 C++ 异常/错误码转换为 LinohException 抛到 Java 侧
// ============================================================================
void throw_linoh_exception(JNIEnv *env, const char *msg);

// ============================================================================
// 全局 JavaVM 缓存（JNI_OnLoad 时设置）
// ============================================================================
JavaVM *get_cached_jvm();
void set_cached_jvm(JavaVM *vm);

}  // namespace linoh::jni
