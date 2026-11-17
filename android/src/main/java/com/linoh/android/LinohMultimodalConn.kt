package com.linoh.android

import java.util.concurrent.atomic.AtomicBoolean

/**
 * linoh 多模态连接对：控制连接 (ctrl/1) + 数据连接 (pp-*/1)。
 *
 * 持有 native `linoh_multimodal_conn_t*` 句柄，封装多模态连接对的访问与释放。
 *
 * **设计**：根据 P5-A 多模态通信架构，每个 [LinohMultimodalConn] 包含两个独立的
 * [LinohConnection]：
 * - **控制连接**（ALPN=ctrl/1）：承载 RPC、心跳、状态上报等控制面消息，可靠 stream
 * - **数据连接**（ALPN=pp-*/1）：承载推理数据（hidden_state / 图片 / 视频 / 音频特征），
 *   多 stream 并行，互不阻塞控制连接
 *
 * **生命周期**：使用完毕必须调用 [close]（或 `use { ... }`）释放底层资源，
 * 否则会泄漏两个 native connection 及底层 QUIC 连接。
 *
 * **子连接视图**（v1.4.2 P0-#3 修复）：[ctrlConn] 和 [dataConn] 现在返回
 * [LinohConnectionView]（只读视图），不暴露 close() 方法，避免外部误调释放
 * 父 [LinohMultimodalConn] 持有的子连接 native 句柄导致 use-after-free。
 *
 * **幂等保证**（v1.4.2 P0-#1 修复）：[close] 可多次调用。
 *
 * @param handle native 句柄（linoh_multimodal_conn_t*）
 */
public class LinohMultimodalConn(
    @JvmField internal val handle: Long,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    /**
     * 获取控制连接（ALPN=ctrl/1）的只读视图。
     *
     * v1.4.2 P0-#3: 返回 [LinohConnectionView] 而非 [LinohConnection]，禁用 close()
     * 以保护父对象持有的 native 资源。视图生命周期与本对象绑定。
     *
     * @return 控制连接视图；本对象已 [close] 或句柄无效时返回 null
     */
    public fun ctrlConn(): LinohConnectionView? {
        if (closed.get()) return null
        val connHandle = nativeCtrlConn(handle)
        return if (connHandle == 0L) null else LinohConnectionView(connHandle)
    }

    /**
     * 获取数据连接（ALPN=pp-*/1）的只读视图。
     *
     * v1.4.2 P0-#3: 返回 [LinohConnectionView] 而非 [LinohConnection]，禁用 close()
     * 以保护父对象持有的 native 资源。视图生命周期与本对象绑定。
     *
     * @return 数据连接视图；本对象已 [close] 或句柄无效时返回 null
     */
    public fun dataConn(): LinohConnectionView? {
        if (closed.get()) return null
        val connHandle = nativeDataConn(handle)
        return if (connHandle == 0L) null else LinohConnectionView(connHandle)
    }

    /**
     * 获取数据通道类型。
     *
     * @return 当前数据连接的 [LinohChannel]；本对象已 [close] 时返回 [LinohChannel.CONTROL]
     */
    public fun dataChannel(): LinohChannel =
        LinohChannel.from(nativeDataChannel(handle))

    /**
     * 释放多模态连接对（会关闭 ctrl + data 两个连接）。
     *
     * v1.4.2 P0-#1: 幂等保护，可多次调用。
     * 释放后本对象不可再使用，[ctrlConn] / [dataConn] 返回的视图也不可再使用。
     */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            if (handle != 0L) {
                nativeFree(handle)
            }
        }
    }

    // --- native 方法签名（与 linoh_jni.cpp 一致） ---
    private external fun nativeCtrlConn(handle: Long): Long
    private external fun nativeDataConn(handle: Long): Long
    private external fun nativeDataChannel(handle: Long): Int
    private external fun nativeFree(handle: Long)
}
