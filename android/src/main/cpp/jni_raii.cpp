// jni_raii.cpp — linoh-android JNI RAII 工具类实现

#include "jni_raii.hpp"

#include <android/log.h>

#include <cstring>

#define LOG_TAG "linoh_jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)

namespace linoh::jni {

// ---------------------------------------------------------------------------
// 全局 JavaVM 缓存
// ---------------------------------------------------------------------------
namespace {
JavaVM *g_jvm = nullptr;
}

JavaVM *get_cached_jvm() { return g_jvm; }
void set_cached_jvm(JavaVM *vm) { g_jvm = vm; }

// ---------------------------------------------------------------------------
// JniEnvGuard 实现
// ---------------------------------------------------------------------------
JniEnvGuard::JniEnvGuard(JavaVM *vm)
    : vm_(vm), env_(nullptr), attached_(false) {
    if (!vm_) {
        LOGE("JniEnvGuard: JavaVM is null");
        return;
    }
    // 尝试 GetEnv（已附加的线程直接返回）
    jint rc = vm_->GetEnv(reinterpret_cast<void **>(&env_), JNI_VERSION_1_6);
    if (rc == JNI_EDETACHED) {
        // 当前线程未附加，调用 AttachCurrentThread
        rc = vm_->AttachCurrentThread(&env_, nullptr);
        if (rc != JNI_OK) {
            LOGE("JniEnvGuard: AttachCurrentThread failed rc=%d", rc);
            env_ = nullptr;
            return;
        }
        attached_ = true;
    } else if (rc != JNI_OK) {
        LOGE("JniEnvGuard: GetEnv failed rc=%d", rc);
        env_ = nullptr;
    }
}

JniEnvGuard::~JniEnvGuard() {
    if (attached_ && vm_) {
        vm_->DetachCurrentThread();
    }
}

// ---------------------------------------------------------------------------
// jstring 转换
// ---------------------------------------------------------------------------
std::string jstring_to_utf8(JNIEnv *env, jstring jstr) {
    if (!jstr || !env) return {};
    const char *chars = env->GetStringUTFChars(jstr, nullptr);
    if (!chars) return {};
    std::string result(chars);
    env->ReleaseStringUTFChars(jstr, chars);
    return result;
}

jstring utf8_to_jstring(JNIEnv *env, const std::string &str) {
    if (!env) return nullptr;
    return env->NewStringUTF(str.c_str());
}

// ---------------------------------------------------------------------------
// 异常辅助
// ---------------------------------------------------------------------------
void throw_linoh_exception(JNIEnv *env, const char *msg) {
    if (!env || !msg) return;
    jclass cls = env->FindClass("com/linoh/android/LinohException");
    if (!cls) {
        LOGE("LinohException class not found; msg was: %s", msg);
        return;
    }
    env->ThrowNew(cls, msg);
    env->DeleteLocalRef(cls);
}

}  // namespace linoh::jni
