package com.linoh.android

import java.util.concurrent.atomic.AtomicBoolean
import kotlin.Function1
import kotlin.Unit

/**
 * linoh Endpoint：UDP 监听器 + 连接发起器。
 *
 * 持有 native `linoh_endpoint_t*` 句柄，封装创建、轮询、连接、释放等操作。
 *
 * **生命周期**：使用完毕必须调用 [close]（或 `use { ... }`）释放底层资源，
 * 否则会泄漏 native endpoint 及其内部连接。
 *
 * **幂等保证**：[close] 是幂等的，可多次调用（v1.4.2 P0-#1 修复），重复调用
 * 不会触发 use-after-free。
 *
 * **回调说明**：4 个回调接口通过 native 层 GlobalRef 长期持有，在 linoh
 * 接收线程触发时通过 `linoh_endpoint_set_user_data` 注入的 handle_storage
 * 反查 Kotlin 回调对象并调用（C-2 阶段已启用实际触发）。
 *
 * @param config Endpoint 配置
 * @param onConnection 入站连接到达回调（connection accepted by peer）
 * @param onStream 流数据到达回调
 * @param onConnState 连接状态变化回调
 * @param onClose 连接关闭回调
 */
public class LinohEndpoint(
    config: LinohEndpointConfig,
    onConnection: Function1<LinohConnection, Unit>? = null,
    onStream: Function1<LinohStream, Unit>? = null,
    onConnState: Function1<ConnState, Unit>? = null,
    onClose: Function1<Unit, Unit>? = null,
) : AutoCloseable {

    private val handle: Long
    private val closed = AtomicBoolean(false)

    init {
        Linoh.ensureLoaded()
        handle = nativeCreate(
            config.secretKey,
            config.alpn,
            config.udpPort,
            onConnection,
            onStream,
            onConnState,
            onClose,
        )
        if (handle == 0L) {
            throw LinohException("linoh_endpoint_create returned null")
        }
    }

    /**
     * 获取本节点 EndpointId（公钥，32 字节）。
     * @return 32 字节 ByteArray
     */
    public fun id(): ByteArray = nativeId(handle)

    /**
     * 获取本地 UDP 监听端口（主机字节序）。
     * 若配置时 udpPort=0，此处返回系统分配的实际端口。
     */
    public fun udpPort(): Int = nativeUdpPort(handle)

    /**
     * 轮询一次：处理内部 UDP 接收、accept、回调触发。
     *
     * @return 触发的事件数（0 = 无事发生）
     *
     * 推荐在游戏循环 / select() / Handler.postDelayed 中周期调用。
     */
    public fun poll(): Int = nativePoll(handle)

    /**
     * 主动连接到远程端点。
     *
     * @param host 对端 IP 地址（如 "127.0.0.1"）
     * @param port 对端 UDP 端口
     * @return 新建连接 [LinohConnection]
     * @throws LinohException 连接失败
     */
    public fun connect(host: String, port: Int): LinohConnection {
        val connHandle = nativeConnect(handle, host, port)
        if (connHandle == 0L) {
            throw LinohException("linoh_endpoint_connect failed: $host:$port")
        }
        return LinohConnection(connHandle)
    }

    /**
     * 主动建立多模态连接对（控制连接 + 数据连接）。
     *
     * 对应 P5-A 多模态通信架构：根据 [channel] 类型建立两个独立的 QUIC 连接，
     * 控制连接走 `ctrl/1` ALPN 承载 RPC/心跳，数据连接走 `pp-*/1` ALPN 承载
     * 推理数据，两连接独立 stream 池互不阻塞。
     *
     * **阻塞语义**：本方法阻塞直到两个连接都建立完成或失败。失败时会自动清理
     * 已建立的连接并返回 null（不会泄漏资源）。
     *
     * @param host 对端 IP 地址（如 "127.0.0.1"）
     * @param port 对端 UDP 端口
     * @param channel 数据通道类型（不应为 [LinohChannel.CONTROL]，那是内部使用的）
     * @return 新建 [LinohMultimodalConn]；连接失败返回 null
     */
    public fun connectMultimodal(
        host: String,
        port: Int,
        channel: LinohChannel,
    ): LinohMultimodalConn? {
        val pairHandle = nativeConnectMultimodal(handle, host, port, channel.value)
        return if (pairHandle == 0L) null else LinohMultimodalConn(pairHandle)
    }

    override fun close() {
        // v1.4.2 P0-#1: 幂等保护，避免重复 close 触发 native 端 use-after-free
        if (closed.compareAndSet(false, true)) {
            if (handle != 0L) {
                nativeFree(handle)
            }
        }
    }

    // --- native 方法签名（与 linoh_jni.cpp 一致） ---
    private external fun nativeCreate(
        secretKey: ByteArray,
        alpn: String,
        udpPort: Int,
        onConnection: Function1<LinohConnection, Unit>?,
        onStream: Function1<LinohStream, Unit>?,
        onConnState: Function1<ConnState, Unit>?,
        onClose: Function1<Unit, Unit>?,
    ): Long

    private external fun nativeFree(handle: Long)
    private external fun nativeId(handle: Long): ByteArray
    private external fun nativeUdpPort(handle: Long): Int
    private external fun nativePoll(handle: Long): Int
    private external fun nativeConnect(handle: Long, host: String, port: Int): Long
    private external fun nativeConnectMultimodal(
        handle: Long,
        host: String,
        port: Int,
        channel: Int,
    ): Long
}
