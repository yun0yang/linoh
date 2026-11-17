package com.linoh.android

import java.util.concurrent.atomic.AtomicBoolean

/**
 * linoh 连接：一个 QUIC 连接。
 *
 * 持有 native `linoh_connection_t*` 句柄，封装状态查询、流操作、关闭等。
 *
 * **生命周期**：使用完毕必须调用 [close]（或 `use { ... }`）释放底层资源。
 *
 * **API 语义分层**（v1.4.2 P0-#2 修复）：
 * - [shutdown] / [shutdownImmediate]：协议层关闭（发送 CONNECTION_CLOSE 帧）
 * - [close]（AutoCloseable）：native 句柄释放（资源回收）
 * 调用顺序：先 [shutdown] 通知对端，再 [close] 释放资源。
 *
 * **幂等保证**：[close] 是幂等的，可多次调用（v1.4.2 P0-#1 修复）。
 *
 * **回调创建**：通过 [LinohEndpoint.connect] 或入站回调获得，外部不应直接构造
 * （构造函数为 internal，仅供 native 回调桥接使用）。
 *
 * @param handle native 句柄（linoh_connection_t*）
 */
public class LinohConnection(
    @JvmField internal val handle: Long,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    /**
     * 连接当前状态。
     */
    public fun state(): ConnState = ConnState.from(nativeState(handle))

    /**
     * 对端 EndpointId（公钥，32 字节）。
     * 连接未完成握手时可能返回全零。
     */
    public fun peerId(): ByteArray = nativePeerId(handle)

    /**
     * 连接 ALPN 协议标识（如 "ctrl/1"）。
     */
    public fun alpn(): String? = nativeAlpn(handle)

    /**
     * 连接统计信息。
     * @return [Stats] data class
     */
    public fun stats(): Stats {
        val out = LongArray(4)
        nativeStats(handle, out)
        return Stats(
            packetsSent = out[0],
            packetsReceived = out[1],
            bytesSent = out[2],
            bytesReceived = out[3],
        )
    }

    /**
     * 优雅关闭连接（协议层，发送 CONNECTION_CLOSE 帧）。
     *
     * 进入 Closing → Draining → Closed 状态，对端会收到 CONNECTION_CLOSE 帧
     * 并立即感知断开。
     *
     * v1.4.2 P0-#2: 由原 `close(errorCode, reason)` 重命名为 `shutdown()`，
     * 避免与 [AutoCloseable.close] 语义混淆。
     *
     * @param errorCode QUIC 应用错误码，0 表示正常关闭
     * @param reason 可读原因字符串，null/空表示无原因
     */
    public fun shutdown(errorCode: Int = 0, reason: String? = null) {
        // shutdown 可多次调用（发送 CONNECTION_CLOSE 帧是幂等的协议动作）
        nativeClose(handle, errorCode, reason)
    }

    /**
     * 立即关闭连接（跳过 draining period，直接 Closed）。
     *
     * 代价：对端可能要靠心跳超时才发现本端退出。
     * 适用于应用主动退出场景。
     *
     * v1.4.2 P0-#2: 命名调整为 `shutdownImmediate`，与 `shutdown` 形成协议关闭对。
     *
     * @param errorCode QUIC 应用错误码
     * @param reason 可读原因字符串
     */
    public fun shutdownImmediate(errorCode: Int = 0, reason: String? = null) {
        nativeCloseImmediate(handle, errorCode, reason)
    }

    /**
     * 打开一条新的双向 Stream。
     * @return 新建 [LinohStream]
     * @throws LinohException 失败
     */
    public fun openStream(): LinohStream {
        val streamHandle = nativeOpenStream(handle)
        if (streamHandle == 0L) {
            throw LinohException("linoh_connection_open_stream failed")
        }
        return LinohStream(streamHandle)
    }

    /**
     * 尝试接收一条已就绪的入站 Stream。
     * @return 入站 [LinohStream]，无入站时返回 null
     */
    public fun acceptStream(): LinohStream? {
        val streamHandle = nativeAcceptStream(handle)
        return if (streamHandle == 0L) null else LinohStream(streamHandle)
    }

    /**
     * 立即刷新发送缓冲区：构建 1-RTT 包并通过 raw socket 发送。
     * @return 实际发送字节数，0 表示无待发送数据或连接未建立
     */
    public fun flush(): Long = nativeFlush(handle)

    /**
     * 释放 native 句柄（资源回收）。
     *
     * v1.4.2 P0-#1: 幂等保护，可多次调用。
     * v1.4.2 P0-#2: 仅做资源释放，协议层关闭请用 [shutdown]。
     */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            if (handle != 0L) {
                nativeFree(handle)
            }
        }
    }

    /** 连接统计快照。 */
    public data class Stats(
        public val packetsSent: Long,
        public val packetsReceived: Long,
        public val bytesSent: Long,
        public val bytesReceived: Long,
    )

    // --- native 方法签名 ---
    private external fun nativeFree(handle: Long)
    private external fun nativeState(handle: Long): Int
    private external fun nativePeerId(handle: Long): ByteArray
    private external fun nativeAlpn(handle: Long): String?
    private external fun nativeStats(handle: Long, outStats: LongArray)
    private external fun nativeClose(handle: Long, errorCode: Int, reason: String?)
    private external fun nativeCloseImmediate(handle: Long, errorCode: Int, reason: String?)
    private external fun nativeOpenStream(handle: Long): Long
    private external fun nativeAcceptStream(handle: Long): Long
    private external fun nativeFlush(handle: Long): Long
}
