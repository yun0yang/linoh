// linoh_jni.cpp — linoh-android JNI 桥接层核心
//
// 实现 Kotlin 包装类（com.linoh.android.*）的 native 方法，
// 调用 linoh C-API（linoh_c.h）完成实际工作。
//
// 设计要点：
//   1. Kotlin 类持有 `private val handle: Long`，作为不透明指针传递给 native
//   2. 4 个回调接口通过 GlobalRef 长期持有 Kotlin Function1 实例
//   3. 回调触发时通过 JniEnvGuard 自动附加当前线程
//   4. 符号可见性 -fvisibility=hidden，仅 JNIEXPORT 入口可见
//
// 阶段 B 暴露的 API 子集（基于 linoh_c.h）：
//   - Linoh.nativeVersion()
//   - LinohEndpoint: create/free/id/udpPort/poll/connect
//   - LinohEndpoint 回调: onConnection/onStream/onConnState/onClose
//   - LinohConnection: free/state/peerId/alpn/stats/close/closeImmediate
//                      openStream/acceptStream/flush
//   - LinohStream: free/id/hasReadable/read/write/finish/isFinished/isClosed

#include "jni_raii.hpp"

#include "linoh/linoh_c.h"

#include <android/log.h>
#include <jni.h>

#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>

#define LOG_TAG "linoh_jni"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

namespace {

// ============================================================================
// 回调上下文：每个 LinohEndpoint 实例对应一个 CallbackContext
// ============================================================================
struct CallbackContext {
    // 4 个 Kotlin Function1<*, Unit> 实例的 GlobalRef（jobject）
    // 类型：kotlin.jvm.functions.Function1
    jobject on_connection_cb = nullptr;  // (LinohConnection) -> Unit
    jobject on_stream_cb = nullptr;      // (LinohStream) -> Unit
    jobject on_conn_state_cb = nullptr;  // (ConnState) -> Unit
    jobject on_close_cb = nullptr;       // (Unit) -> Unit

    // JavaVM 引用（用于回调时附加线程）
    JavaVM *jvm = nullptr;

    // Kotlin 类/方法缓存
    jclass linoh_connection_cls = nullptr;
    jclass linoh_stream_cls = nullptr;
    jclass conn_state_cls = nullptr;
    jmethodID connection_ctor = nullptr;  // LinohConnection(long)
    jmethodID stream_ctor = nullptr;      // LinohStream(long)
    jmethodID conn_state_from_value = nullptr;  // ConnState.from(int)
    // v1.4.3 P2-#3: 缓存 Function1.invoke 方法，4 个 bridge 函数共用，避免每次回调
    // 重复 GetObjectClass + GetMethodID + DeleteLocalRef 三步。
    jmethodID func1_invoke_m = nullptr;   // Function1.invoke(Object)Object

    // C-2: handle_storage 指针，通过 linoh_endpoint_set_user_data 注入 linoh
    // linoh 回调触发时通过 user_data 参数传回，回调内 *handle_storage 即 endpoint handle
    // nativeFree 中 delete 此指针
    int64_t *handle_storage = nullptr;

    ~CallbackContext() {
        // GlobalRef 释放在 LinohEndpoint.nativeFree 中显式处理
    }
};

// 全局回调上下文表：endpoint handle -> CallbackContext
std::mutex g_ctx_mutex;
std::unordered_map<int64_t, std::shared_ptr<CallbackContext>> g_ctx_table;

// 通过 endpoint handle 查找回调上下文
std::shared_ptr<CallbackContext> find_ctx(int64_t handle) {
    std::lock_guard<std::mutex> lock(g_ctx_mutex);
    auto it = g_ctx_table.find(handle);
    return it != g_ctx_table.end() ? it->second : nullptr;
}

// ============================================================================
// C-API 回调桥接（linoh_c.h 注册的回调函数指针 → Kotlin Function1 调用）
// ============================================================================
void on_connection_cb_bridge(linoh_connection_t *conn, void *user_data) {
    auto *handle_ptr = static_cast<int64_t *>(user_data);
    if (!handle_ptr || !conn) return;
    auto ctx = find_ctx(*handle_ptr);
    if (!ctx || !ctx->on_connection_cb) return;

    linoh::jni::JniEnvGuard env_guard(ctx->jvm);
    JNIEnv *env = env_guard.env();
    if (!env) return;

    // 构造 LinohConnection Kotlin 对象
    jobject kconn = env->NewObject(ctx->linoh_connection_cls,
                                   ctx->connection_ctor,
                                   static_cast<jlong>(reinterpret_cast<intptr_t>(conn)));
    if (!kconn) {
        LOGE("on_connection_cb_bridge: NewObject LinohConnection failed");
        return;
    }

    // 调用 Function1.invoke(kconn)
    // v1.4.3 P2-#3: 使用 ctx 缓存的 func1_invoke_m，避免每次回调 GetObjectClass+GetMethodID。
    if (!ctx->func1_invoke_m) {
        LOGE("on_connection_cb_bridge: func1_invoke_m not cached");
        return;
    }
    env->CallObjectMethod(ctx->on_connection_cb, ctx->func1_invoke_m, kconn);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void on_stream_cb_bridge(linoh_stream_t *stream, void *user_data) {
    auto *handle_ptr = static_cast<int64_t *>(user_data);
    if (!handle_ptr || !stream) return;
    auto ctx = find_ctx(*handle_ptr);
    if (!ctx || !ctx->on_stream_cb) return;

    linoh::jni::JniEnvGuard env_guard(ctx->jvm);
    JNIEnv *env = env_guard.env();
    if (!env) return;

    jobject kstream = env->NewObject(ctx->linoh_stream_cls,
                                     ctx->stream_ctor,
                                     static_cast<jlong>(reinterpret_cast<intptr_t>(stream)));
    if (!kstream) {
        LOGE("on_stream_cb_bridge: NewObject LinohStream failed");
        return;
    }
    linoh::jni::JniLocalRef<jobject> kstream_ref(env, kstream);
    // v1.4.3 P2-#3: 使用 ctx 缓存的 func1_invoke_m。
    if (!ctx->func1_invoke_m) {
        LOGE("on_stream_cb_bridge: func1_invoke_m not cached");
        return;
    }
    env->CallObjectMethod(ctx->on_stream_cb, ctx->func1_invoke_m, kstream);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void on_conn_state_cb_bridge(linoh_connection_t *conn, linoh_conn_state_t state, void *user_data) {
    auto *handle_ptr = static_cast<int64_t *>(user_data);
    if (!handle_ptr) return;
    auto ctx = find_ctx(*handle_ptr);
    if (!ctx || !ctx->on_conn_state_cb) return;

    linoh::jni::JniEnvGuard env_guard(ctx->jvm);
    JNIEnv *env = env_guard.env();
    if (!env) return;

    // 调用 ConnState.from(state) 获取 Kotlin enum
    jobject state_enum = env->CallStaticObjectMethod(ctx->conn_state_cls,
                                                     ctx->conn_state_from_value,
                                                     static_cast<jint>(state));
    if (!state_enum) {
        LOGE("on_conn_state_cb_bridge: ConnState.from returned null");
        return;
    }
    linoh::jni::JniLocalRef<jobject> state_ref(env, state_enum);

    // v1.4.3 P2-#3: 使用 ctx 缓存的 func1_invoke_m。
    if (!ctx->func1_invoke_m) {
        LOGE("on_conn_state_cb_bridge: func1_invoke_m not cached");
        return;
    }
    env->CallObjectMethod(ctx->on_conn_state_cb, ctx->func1_invoke_m, state_enum);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

void on_close_cb_bridge(linoh_connection_t * /*conn*/, void *user_data) {
    auto *handle_ptr = static_cast<int64_t *>(user_data);
    if (!handle_ptr) return;
    auto ctx = find_ctx(*handle_ptr);
    if (!ctx || !ctx->on_close_cb) return;

    linoh::jni::JniEnvGuard env_guard(ctx->jvm);
    JNIEnv *env = env_guard.env();
    if (!env) return;

    // onClose: () -> Unit，invoke 参数为 Unit.INSTANCE
    jclass unit_cls = env->FindClass("kotlin/Unit");
    if (!unit_cls) return;
    jfieldID instance_field = env->GetStaticFieldID(unit_cls, "INSTANCE", "Lkotlin/Unit;");
    jobject unit_instance = env->GetStaticObjectField(unit_cls, instance_field);
    env->DeleteLocalRef(unit_cls);
    if (!unit_instance) return;
    linoh::jni::JniLocalRef<jobject> unit_ref(env, unit_instance);

    // v1.4.3 P2-#3: 使用 ctx 缓存的 func1_invoke_m。
    if (!ctx->func1_invoke_m) {
        LOGE("on_close_cb_bridge: func1_invoke_m not cached");
        return;
    }
    env->CallObjectMethod(ctx->on_close_cb, ctx->func1_invoke_m, unit_instance);
    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
    }
}

}  // anonymous namespace

// ============================================================================
// JNI_OnLoad：缓存 JavaVM，预解析 Kotlin 类
// ============================================================================
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void * /*reserved*/) {
    linoh::jni::set_cached_jvm(vm);
    LOGI("linoh_jni loaded (linoh v%s)", linoh_version());
    return JNI_VERSION_1_6;
}

// ============================================================================
// Linoh.kt: native methods
// ============================================================================
extern "C" {

JNIEXPORT jstring JNICALL
Java_com_linoh_android_Linoh_nativeVersion(JNIEnv *env, jobject /*thiz*/) {
    // v1.4.3 P2-#5: NewStringUTF NULL 兜底 — linoh_version() 理论上不会返回 nullptr，
    // 但 JNI 规范要求 NewStringUTF 入参非 NULL（传入 NULL 会抛 NullPointerException）。
    // 这里加 NULL 检查保证 OOM/初始化异常场景下仍能返回 "unknown" 字符串。
    const char *ver = linoh_version();
    if (!ver) ver = "unknown";
    return env->NewStringUTF(ver);
}

// ---------------------------------------------------------------------------
// LinohEndpoint.kt: native methods
// ---------------------------------------------------------------------------

// private external fun nativeCreate(
//     secretKey: ByteArray, alpn: String, udpPort: Int,
//     onConnection: Function1<LinohConnection, Unit>?,
//     onStream: Function1<LinohStream, Unit>?,
//     onConnState: Function1<ConnState, Unit>?,
//     onClose: Function1<Unit, Unit>?
// ): Long
JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohEndpoint_nativeCreate(
    JNIEnv *env, jobject /*thiz*/,
    jbyteArray secret_key, jstring alpn, jint udp_port,
    jobject on_connection, jobject on_stream, jobject on_conn_state, jobject on_close) {

    if (!secret_key || !alpn) {
        linoh::jni::throw_linoh_exception(env, "secretKey or alpn is null");
        return 0;
    }

    // 提取 secretKey
    jsize sk_len = env->GetArrayLength(secret_key);
    if (sk_len != LINOH_KEY_SIZE) {
        linoh::jni::throw_linoh_exception(env, "secretKey must be 32 bytes");
        return 0;
    }
    jbyte *sk_bytes = env->GetByteArrayElements(secret_key, nullptr);
    if (!sk_bytes) {
        linoh::jni::throw_linoh_exception(env, "GetByteArrayElements failed");
        return 0;
    }

    std::string alpn_str = linoh::jni::jstring_to_utf8(env, alpn);

    // 构造 linoh_endpoint_config_t
    linoh_endpoint_config_t config{};
    std::memcpy(config.secret_key.bytes, sk_bytes, LINOH_KEY_SIZE);
    config.alpn = alpn_str.c_str();
    config.udp_port = static_cast<uint16_t>(udp_port);
    config.user_data = nullptr;  // 设置在 create 之后

    env->ReleaseByteArrayElements(secret_key, sk_bytes, JNI_ABORT);

    // 创建 endpoint
    linoh_endpoint_t *ep = linoh_endpoint_create(&config);
    if (!ep) {
        linoh::jni::throw_linoh_exception(env, "linoh_endpoint_create failed");
        return 0;
    }

    int64_t handle = reinterpret_cast<intptr_t>(ep);

    // 注册回调
    if (on_connection || on_stream || on_conn_state || on_close) {
        auto ctx = std::make_shared<CallbackContext>();
        ctx->jvm = linoh::jni::get_cached_jvm();

        // 缓存 Kotlin 类/方法
        jclass conn_cls = env->FindClass("com/linoh/android/LinohConnection");
        if (conn_cls) {
            ctx->linoh_connection_cls = static_cast<jclass>(env->NewGlobalRef(conn_cls));
            ctx->connection_ctor = env->GetMethodID(ctx->linoh_connection_cls, "<init>", "(J)V");
            env->DeleteLocalRef(conn_cls);
        }
        jclass stream_cls = env->FindClass("com/linoh/android/LinohStream");
        if (stream_cls) {
            ctx->linoh_stream_cls = static_cast<jclass>(env->NewGlobalRef(stream_cls));
            ctx->stream_ctor = env->GetMethodID(ctx->linoh_stream_cls, "<init>", "(J)V");
            env->DeleteLocalRef(stream_cls);
        }
        jclass state_cls = env->FindClass("com/linoh/android/ConnState");
        if (state_cls) {
            ctx->conn_state_cls = static_cast<jclass>(env->NewGlobalRef(state_cls));
            ctx->conn_state_from_value = env->GetStaticMethodID(
                ctx->conn_state_cls, "from", "(I)Lcom/linoh/android/ConnState;");
            env->DeleteLocalRef(state_cls);
        }

        // GlobalRef Kotlin Function1
        if (on_connection) ctx->on_connection_cb = env->NewGlobalRef(on_connection);
        if (on_stream) ctx->on_stream_cb = env->NewGlobalRef(on_stream);
        if (on_conn_state) ctx->on_conn_state_cb = env->NewGlobalRef(on_conn_state);
        if (on_close) ctx->on_close_cb = env->NewGlobalRef(on_close);

        // v1.4.3 P2-#3: 缓存 Function1.invoke 方法到 ctx。
        // 4 个 Kotlin Function1 共享同一方法签名（Function1<P1, R>.invoke(P1)R），
        // 用任意一个实例的 class 查找即可。注意：是 invoke 方法（不是 invokeSuspend）。
        // 任一 Function1 实例非空时缓存；全部为空（无回调）时无需缓存。
        jobject any_func1 = on_connection ? on_connection
                            : on_stream ? on_stream
                            : on_conn_state ? on_conn_state
                            : on_close;  // 可能为 null（无回调场景）
        if (any_func1) {
            jclass func_cls = env->GetObjectClass(any_func1);
            if (func_cls) {
                jmethodID mid = env->GetMethodID(func_cls, "invoke",
                                                  "(Ljava/lang/Object;)Ljava/lang/Object;");
                env->DeleteLocalRef(func_cls);
                ctx->func1_invoke_m = mid;
            }
        }

        // C-2: 通过 linoh_endpoint_set_user_data 把 handle_storage 注入 endpoint
        // linoh 回调触发时通过 user_data 参数传回 handle_storage 指针，
        // 回调内 *handle_storage 即 endpoint handle，用于查 g_ctx_table 反查 ctx。
        //
        // 生命周期：handle_storage 在 nativeFree 中 delete。
        // 线程安全：linoh_c.cpp 中 user_data 为 atomic<void*>，set 与回调 load 无锁同步。
        ctx->handle_storage = new int64_t(handle);
        linoh_endpoint_set_user_data(ep, ctx->handle_storage);

        // 注册 4 个 C-API 回调（linoh 在 recv_thread 中触发，通过 user_data 传 handle_storage）
        linoh_endpoint_on_connection(ep, on_connection_cb_bridge);
        linoh_endpoint_on_stream(ep, on_stream_cb_bridge);
        linoh_endpoint_on_conn_state(ep, on_conn_state_cb_bridge);
        linoh_endpoint_on_close(ep, on_close_cb_bridge);

        // 注入 g_ctx_table（回调内通过 *handle_storage 查表获取 ctx）
        {
            std::lock_guard<std::mutex> lock(g_ctx_mutex);
            g_ctx_table[handle] = ctx;
        }
    }

    return static_cast<jlong>(handle);
}

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohEndpoint_nativeFree(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return;
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));

    // C-2: 按正确顺序清理，避免回调线程访问已释放资源
    // 1) 从 g_ctx_table erase（防止回调通过 handle 查到已释放的 ctx）
    std::shared_ptr<CallbackContext> ctx;
    {
        std::lock_guard<std::mutex> lock(g_ctx_mutex);
        auto it = g_ctx_table.find(static_cast<int64_t>(handle));
        if (it != g_ctx_table.end()) {
            ctx = it->second;
            g_ctx_table.erase(it);
        }
    }

    // 2) linoh_endpoint_free 会停止 recv_thread 并 join，确保回调不再触发
    //    必须在释放 GlobalRef 之前调用，否则回调线程可能访问已 Delete 的 GlobalRef 导致崩溃
    linoh_endpoint_free(ep);

    // 3) recv_thread 已 join，安全释放 ctx 资源
    if (ctx) {
        // delete handle_storage（C-2 新增）
        if (ctx->handle_storage) {
            delete ctx->handle_storage;
            ctx->handle_storage = nullptr;
        }
        // 释放 GlobalRef
        if (ctx->on_connection_cb) { env->DeleteGlobalRef(ctx->on_connection_cb); ctx->on_connection_cb = nullptr; }
        if (ctx->on_stream_cb) { env->DeleteGlobalRef(ctx->on_stream_cb); ctx->on_stream_cb = nullptr; }
        if (ctx->on_conn_state_cb) { env->DeleteGlobalRef(ctx->on_conn_state_cb); ctx->on_conn_state_cb = nullptr; }
        if (ctx->on_close_cb) { env->DeleteGlobalRef(ctx->on_close_cb); ctx->on_close_cb = nullptr; }
        if (ctx->linoh_connection_cls) { env->DeleteGlobalRef(ctx->linoh_connection_cls); ctx->linoh_connection_cls = nullptr; }
        if (ctx->linoh_stream_cls) { env->DeleteGlobalRef(ctx->linoh_stream_cls); ctx->linoh_stream_cls = nullptr; }
        if (ctx->conn_state_cls) { env->DeleteGlobalRef(ctx->conn_state_cls); ctx->conn_state_cls = nullptr; }
        // ctx 是 shared_ptr，离开作用域自动析构
    }
}

JNIEXPORT jbyteArray JNICALL
Java_com_linoh_android_LinohEndpoint_nativeId(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return nullptr;
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));
    const linoh_endpoint_id_t *id = linoh_endpoint_id(ep);
    if (!id) return nullptr;
    jbyteArray arr = env->NewByteArray(LINOH_KEY_SIZE);
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, LINOH_KEY_SIZE,
                            reinterpret_cast<const jbyte *>(id->bytes));
    return arr;
}

JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohEndpoint_nativeUdpPort(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));
    return static_cast<jint>(linoh_endpoint_udp_port(ep));
}

JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohEndpoint_nativePoll(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));
    return static_cast<jint>(linoh_endpoint_poll(ep));
}

JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohEndpoint_nativeConnect(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jstring host, jint port) {
    if (!handle || !host) {
        linoh::jni::throw_linoh_exception(env, "handle or host is null");
        return 0;
    }
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));
    std::string host_str = linoh::jni::jstring_to_utf8(env, host);
    linoh_connection_t *conn = linoh_endpoint_connect(ep, host_str.c_str(),
                                                       static_cast<uint16_t>(port));
    if (!conn) {
        linoh::jni::throw_linoh_exception(env, "linoh_endpoint_connect failed");
        return 0;
    }
    return static_cast<jlong>(reinterpret_cast<intptr_t>(conn));
}

// private external fun nativeConnectMultimodal(handle: Long, host: String, port: Int, channel: Int): Long
JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohEndpoint_nativeConnectMultimodal(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jstring host, jint port, jint channel) {
    if (!handle || !host) {
        linoh::jni::throw_linoh_exception(env, "handle or host is null");
        return 0;
    }
    // CONTROL(0) 仅供内部使用，外部不应直接指定
    if (channel == LINOH_CHANNEL_CONTROL) {
        linoh::jni::throw_linoh_exception(env, "channel must not be CONTROL(0)");
        return 0;
    }
    auto *ep = reinterpret_cast<linoh_endpoint_t *>(static_cast<intptr_t>(handle));
    std::string host_str = linoh::jni::jstring_to_utf8(env, host);
    linoh_multimodal_conn_t *pair = linoh_endpoint_connect_multimodal(
        ep, host_str.c_str(), static_cast<uint16_t>(port),
        static_cast<linoh_multimodal_channel_t>(channel));
    // 失败时返回 0（linoh 内部已清理已建立连接，不泄漏资源）
    if (!pair) return 0;
    return static_cast<jlong>(reinterpret_cast<intptr_t>(pair));
}

// ---------------------------------------------------------------------------
// LinohMultimodalConn.kt: native methods
// ---------------------------------------------------------------------------

// private external fun nativeCtrlConn(handle: Long): Long
JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohMultimodalConn_nativeCtrlConn(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *pair = reinterpret_cast<linoh_multimodal_conn_t *>(static_cast<intptr_t>(handle));
    linoh_connection_t *conn = linoh_multimodal_ctrl_conn(pair);
    return static_cast<jlong>(reinterpret_cast<intptr_t>(conn));
}

// private external fun nativeDataConn(handle: Long): Long
JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohMultimodalConn_nativeDataConn(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *pair = reinterpret_cast<linoh_multimodal_conn_t *>(static_cast<intptr_t>(handle));
    linoh_connection_t *conn = linoh_multimodal_data_conn(pair);
    return static_cast<jlong>(reinterpret_cast<intptr_t>(conn));
}

// private external fun nativeDataChannel(handle: Long): Int
JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohMultimodalConn_nativeDataChannel(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return static_cast<jint>(LINOH_CHANNEL_CONTROL);
    auto *pair = reinterpret_cast<linoh_multimodal_conn_t *>(static_cast<intptr_t>(handle));
    return static_cast<jint>(linoh_multimodal_data_channel(pair));
}

// private external fun nativeFree(handle: Long)
JNIEXPORT void JNICALL
Java_com_linoh_android_LinohMultimodalConn_nativeFree(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return;
    auto *pair = reinterpret_cast<linoh_multimodal_conn_t *>(static_cast<intptr_t>(handle));
    linoh_multimodal_conn_free(pair);
}

// ---------------------------------------------------------------------------
// LinohConnection.kt: native methods
// ---------------------------------------------------------------------------

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohConnection_nativeFree(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    linoh_connection_free(conn);
}

JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohConnection_nativeState(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return LINOH_CONN_INITIAL;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    return static_cast<jint>(linoh_connection_state(conn));
}

JNIEXPORT jbyteArray JNICALL
Java_com_linoh_android_LinohConnection_nativePeerId(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return nullptr;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    const linoh_endpoint_id_t *id = linoh_connection_peer_id(conn);
    if (!id) return nullptr;
    jbyteArray arr = env->NewByteArray(LINOH_KEY_SIZE);
    if (!arr) return nullptr;
    env->SetByteArrayRegion(arr, 0, LINOH_KEY_SIZE,
                            reinterpret_cast<const jbyte *>(id->bytes));
    return arr;
}

JNIEXPORT jstring JNICALL
Java_com_linoh_android_LinohConnection_nativeAlpn(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return nullptr;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    const char *alpn = linoh_connection_alpn(conn);
    return alpn ? env->NewStringUTF(alpn) : nullptr;
}

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohConnection_nativeStats(
    JNIEnv *env, jobject /*thiz*/, jlong handle,
    jlongArray out_stats) {
    if (!handle || !out_stats) return;
    if (env->GetArrayLength(out_stats) < 4) {
        linoh::jni::throw_linoh_exception(env, "out_stats must have length >= 4");
        return;
    }
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    uint64_t sent = 0, recv = 0, bytes_sent = 0, bytes_recv = 0;
    linoh_connection_stats(conn, &sent, &recv, &bytes_sent, &bytes_recv);
    jlong buf[4] = {
        static_cast<jlong>(sent), static_cast<jlong>(recv),
        static_cast<jlong>(bytes_sent), static_cast<jlong>(bytes_recv)
    };
    env->SetLongArrayRegion(out_stats, 0, 4, buf);
}

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohConnection_nativeClose(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jint error_code, jstring reason) {
    if (!handle) return;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    std::string reason_str = reason ? linoh::jni::jstring_to_utf8(env, reason) : std::string{};
    linoh_connection_close(conn, static_cast<uint16_t>(error_code),
                           reason_str.empty() ? nullptr : reason_str.c_str());
}

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohConnection_nativeCloseImmediate(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jint error_code, jstring reason) {
    if (!handle) return;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    std::string reason_str = reason ? linoh::jni::jstring_to_utf8(env, reason) : std::string{};
    linoh_connection_close_immediate(conn, static_cast<uint16_t>(error_code),
                                     reason_str.empty() ? nullptr : reason_str.c_str());
}

JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohConnection_nativeOpenStream(JNIEnv *env, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    linoh_stream_t *stream = linoh_connection_open_stream(conn);
    if (!stream) {
        linoh::jni::throw_linoh_exception(env, "linoh_connection_open_stream failed");
        return 0;
    }
    return static_cast<jlong>(reinterpret_cast<intptr_t>(stream));
}

JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohConnection_nativeAcceptStream(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    linoh_stream_t *stream = linoh_connection_accept_stream(conn);
    return stream ? static_cast<jlong>(reinterpret_cast<intptr_t>(stream)) : 0;
}

JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohConnection_nativeFlush(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *conn = reinterpret_cast<linoh_connection_t *>(static_cast<intptr_t>(handle));
    return static_cast<jlong>(linoh_connection_flush(conn));
}

// ---------------------------------------------------------------------------
// LinohStream.kt: native methods
// ---------------------------------------------------------------------------

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohStream_nativeFree(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    linoh_stream_free(stream);
}

JNIEXPORT jlong JNICALL
Java_com_linoh_android_LinohStream_nativeId(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return 0;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    return static_cast<jlong>(linoh_stream_id(stream));
}

JNIEXPORT jboolean JNICALL
Java_com_linoh_android_LinohStream_nativeHasReadable(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return JNI_FALSE;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    return linoh_stream_has_readable(stream) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohStream_nativeRead(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jbyteArray buf, jint off, jint len) {
    if (!handle || !buf) {
        linoh::jni::throw_linoh_exception(env, "handle or buf is null");
        return -1;
    }
    if (off < 0 || len <= 0 || static_cast<jint>(env->GetArrayLength(buf)) < off + len) {
        linoh::jni::throw_linoh_exception(env, "invalid offset/length");
        return -1;
    }
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));

    // 使用 GetByteArrayElements 避免直接指针写入越界
    jbyte *buf_ptr = env->GetByteArrayElements(buf, nullptr);
    if (!buf_ptr) {
        linoh::jni::throw_linoh_exception(env, "GetByteArrayElements failed");
        return -1;
    }
    size_t n = linoh_stream_read(stream,
                                 reinterpret_cast<uint8_t *>(buf_ptr + off),
                                 static_cast<size_t>(len));
    env->ReleaseByteArrayElements(buf, buf_ptr, 0);  // 0 = copy back
    return static_cast<jint>(n);
}

JNIEXPORT jint JNICALL
Java_com_linoh_android_LinohStream_nativeWrite(
    JNIEnv *env, jobject /*thiz*/, jlong handle, jbyteArray buf, jint off, jint len) {
    if (!handle || !buf) {
        linoh::jni::throw_linoh_exception(env, "handle or buf is null");
        return -1;
    }
    if (off < 0 || len <= 0 || static_cast<jint>(env->GetArrayLength(buf)) < off + len) {
        linoh::jni::throw_linoh_exception(env, "invalid offset/length");
        return -1;
    }
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));

    jbyte *buf_ptr = env->GetByteArrayElements(buf, nullptr);
    if (!buf_ptr) {
        linoh::jni::throw_linoh_exception(env, "GetByteArrayElements failed");
        return -1;
    }
    size_t n = linoh_stream_write(stream,
                                  reinterpret_cast<const uint8_t *>(buf_ptr + off),
                                  static_cast<size_t>(len));
    env->ReleaseByteArrayElements(buf, buf_ptr, JNI_ABORT);  // 不需要回写
    return static_cast<jint>(n);
}

JNIEXPORT void JNICALL
Java_com_linoh_android_LinohStream_nativeFinish(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    linoh_stream_finish(stream);
}

JNIEXPORT jboolean JNICALL
Java_com_linoh_android_LinohStream_nativeIsFinished(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return JNI_FALSE;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    return linoh_stream_is_finished(stream) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_linoh_android_LinohStream_nativeIsClosed(JNIEnv * /*env*/, jobject /*thiz*/, jlong handle) {
    if (!handle) return JNI_TRUE;
    auto *stream = reinterpret_cast<linoh_stream_t *>(static_cast<intptr_t>(handle));
    return linoh_stream_is_closed(stream) ? JNI_TRUE : JNI_FALSE;
}

}  // extern "C"
