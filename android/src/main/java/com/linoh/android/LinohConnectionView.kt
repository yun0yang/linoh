package com.linoh.android

/**
 * linoh 连接的只读视图（v1.4.2 P0-#3 新增）。
 *
 * 用途：[LinohMultimodalConn.ctrlConn] / [dataConn] 返回此视图，避免外部误调
 * close()/shutdown() 释放父 [LinohMultimodalConn] 持有的子连接 native 句柄。
 *
 * **API 子集**（仅查询 + 协议层关闭，不暴露资源释放）：
 * - [state] / [peerId] / [alpn] / [stats]：状态查询（不持有 native 资源）
 * - [openStream] / [acceptStream] / [flush]：连接内流操作（不释放连接资源）
 * - [shutdown] / [shutdownImmediate]：协议层关闭（由父 MultimodalConn 整体管理释放）
 *
 * **没有的 API**（与 [LinohConnection] 差异）：
 * - ❌ 无 [close] 方法（不能直接释放 native 句柄）
 * - ❌ 无 [shutdown] 也无 nativeFree — 协议层关闭由父 MultimodalConn 协调
 *
 * **生命周期**：与 [LinohMultimodalConn] 绑定，父对象 close 后本视图不可用。
 *
 * @param handle native 句柄（linoh_connection_t*）
 */
public class LinohConnectionView(
    @JvmField internal val handle: Long,
) {
    /**
     * 连接当前状态。
     */
    public fun state(): ConnState = ConnState.from(nativeState(handle))

    /**
     * 对端 EndpointId（公钥，32 字节）。
     */
    public fun peerId(): ByteArray = nativePeerId(handle)

    /**
     * 连接 ALPN 协议标识（如 "ctrl/1"）。
     */
    public fun alpn(): String? = nativeAlpn(handle)

    /**
     * 连接统计信息。
     */
    public fun stats(): LinohConnection.Stats {
        val out = LongArray(4)
        nativeStats(handle, out)
        return LinohConnection.Stats(
            packetsSent = out[0],
            packetsReceived = out[1],
            bytesSent = out[2],
            bytesReceived = out[3],
        )
    }

    /**
     * 打开一条新的双向 Stream。
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
     */
    public fun acceptStream(): LinohStream? {
        val streamHandle = nativeAcceptStream(handle)
        return if (streamHandle == 0L) null else LinohStream(streamHandle)
    }

    /**
     * 立即刷新发送缓冲区。
     */
    public fun flush(): Long = nativeFlush(handle)

    // --- native 方法签名（复用 LinohConnection 的 native 实现） ---
    private external fun nativeState(handle: Long): Int
    private external fun nativePeerId(handle: Long): ByteArray
    private external fun nativeAlpn(handle: Long): String?
    private external fun nativeStats(handle: Long, outStats: LongArray)
    private external fun nativeOpenStream(handle: Long): Long
    private external fun nativeAcceptStream(handle: Long): Long
    private external fun nativeFlush(handle: Long): Long
}
