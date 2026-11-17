package com.linoh.android

import java.util.concurrent.atomic.AtomicBoolean

/**
 * linoh 流：连接内的双向字节流。
 *
 * 持有 native `linoh_stream_t*` 句柄，封装读、写、半关闭、查询等操作。
 *
 * **生命周期**：使用完毕必须调用 [close]（或 `use { ... }`）释放底层资源。
 *
 * **幂等保证**（v1.4.2 P0-#1 修复）：[close] 可多次调用，不会触发 use-after-free。
 *
 * **缓冲语义**：[write] 写入的数据先进入发送缓冲，需调用 [LinohConnection.flush]
 * 才会真正发出。[read] 在无数据时阻塞直到有数据或 FIN。
 *
 * @param handle native 句柄（linoh_stream_t*）
 */
public class LinohStream(
    @JvmField internal val handle: Long,
) : AutoCloseable {

    private val closed = AtomicBoolean(false)

    /**
     * QUIC Stream ID。
     */
    public fun id(): Long = nativeId(handle)

    /**
     * 是否有可读数据。
     * 返回 true 时，[read] 会立即返回数据。
     */
    public fun hasReadable(): Boolean = nativeHasReadable(handle)

    /**
     * 读取数据到 [buf] 的 [off] 位置，最多 [len] 字节。
     *
     * @param buf 输出缓冲区
     * @param off 起始偏移
     * @param len 最大读取字节数
     * @return 实际读取字节数；0 表示对端已 FIN；-1 表示错误（已抛出 [LinohException]）
     * @throws LinohException 参数非法或 native 调用失败
     */
    public fun read(buf: ByteArray, off: Int = 0, len: Int = buf.size - off): Int {
        if (off < 0 || len <= 0 || buf.size < off + len) {
            throw LinohException("invalid offset/length: off=$off len=$len bufSize=${buf.size}")
        }
        return nativeRead(handle, buf, off, len)
    }

    /**
     * 便捷读取：返回一个新的 ByteArray，包含最多 [maxLen] 字节数据。
     * 若对端 FIN，返回的 ByteArray 长度可能小于 [maxLen] 或为空。
     */
    public fun read(maxLen: Int = 4096): ByteArray {
        val buf = ByteArray(maxLen)
        val n = read(buf, 0, maxLen)
        return if (n <= 0) ByteArray(0) else buf.copyOf(n)
    }

    /**
     * 写入 [buf] 中 [off] 起的 [len] 字节。
     *
     * @return 实际写入字节数（可能小于 [len]，若流缓冲已满）
     * @throws LinohException 参数非法或 native 调用失败
     */
    public fun write(buf: ByteArray, off: Int = 0, len: Int = buf.size - off): Int {
        if (off < 0 || len <= 0 || buf.size < off + len) {
            throw LinohException("invalid offset/length: off=$off len=$len bufSize=${buf.size}")
        }
        return nativeWrite(handle, buf, off, len)
    }

    /**
     * 便捷写入：完整 [data]。
     * @return 实际写入字节数
     */
    public fun write(data: ByteArray): Int = write(data, 0, data.size)

    /**
     * 通知对端本端已完成写入（发送 STREAM with FIN）。
     * 调用后不能再写数据。
     */
    public fun finish() {
        nativeFinish(handle)
    }

    /**
     * 本端是否已发送 FIN。
     */
    public fun isFinished(): Boolean = nativeIsFinished(handle)

    /**
     * 流是否已完全关闭（读写均结束）。
     */
    public fun isClosed(): Boolean = nativeIsClosed(handle)

    /**
     * 释放 Stream 句柄。
     * 必须释放通过 [LinohConnection.openStream]、[LinohConnection.acceptStream]
     * 或回调获得的句柄。
     *
     * v1.4.2 P0-#1: 幂等保护，可多次调用。
     */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            if (handle != 0L) {
                nativeFree(handle)
            }
        }
    }

    // --- native 方法签名 ---
    private external fun nativeFree(handle: Long)
    private external fun nativeId(handle: Long): Long
    private external fun nativeHasReadable(handle: Long): Boolean
    private external fun nativeRead(handle: Long, buf: ByteArray, off: Int, len: Int): Int
    private external fun nativeWrite(handle: Long, buf: ByteArray, off: Int, len: Int): Int
    private external fun nativeFinish(handle: Long)
    private external fun nativeIsFinished(handle: Long): Boolean
    private external fun nativeIsClosed(handle: Long): Boolean
}
