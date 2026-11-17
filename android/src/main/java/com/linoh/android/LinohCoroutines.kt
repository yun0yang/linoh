package com.linoh.android

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * linoh 协程封装：用 kotlinx-coroutines 把阻塞/回调式 API 包装为 suspend/Flow。
 *
 * 提供四类扩展：
 *
 * 1. **阻塞连接 → suspend 连接**：[connectAsync] / [connectMultimodalAsync]
 *    把 `linoh_endpoint_connect` 系列阻塞调用放到 [Dispatchers.IO] 执行
 *
 * 2. **轮询循环**：[pollLoop] 周期性调用 [LinohEndpoint.poll]，驱动回调触发
 *
 * 3. **回调 → Flow**：[flowEndpoint] 工厂把 4 个回调转换为 [Flow]
 *
 * 4. **流写入 → suspend 写入**：[writeAwait] 把 [LinohStream.write] 的同步写入
 *    + `flush` 配合 delay 实现背压
 *
 * **使用示例**：
 * ```
 * val (endpoint, connFlow, streamFlow, stateFlow) = flowEndpoint(config)
 *
 * val scope = CoroutineScope(Dispatchers.IO)
 * val pollJob = scope.launch { endpoint.pollLoop() }     // 启动轮询
 * scope.launch { connFlow.collect { /* 处理入站连接 */ } }
 *
 * val conn = endpoint.connectAsync("127.0.0.1", 9999)
 * // …
 * pollJob.cancel()
 * endpoint.close()
 * ```
 *
 * **注意**：本文件所有扩展函数都假设调用方已导入 kotlinx-coroutines，
 * 编译时需要 `kotlinx-coroutines-core` 依赖（build.gradle.kts 中以 `api` 暴露）。
 */

// ============================================================================
// 1. 阻塞连接 → suspend 连接
// ============================================================================

/**
 * 异步连接到远程端点（suspend 包装）。
 *
 * 把阻塞的 [LinohEndpoint.connect] 调度到 [Dispatchers.IO] 执行，避免阻塞调用协程。
 *
 * @param host 对端 IP 地址
 * @param port 对端 UDP 端口
 * @return 新建 [LinohConnection]
 * @throws LinohException 连接失败
 */
public suspend fun LinohEndpoint.connectAsync(host: String, port: Int): LinohConnection =
    withContext(Dispatchers.IO) {
        connect(host, port)
    }

/**
 * 异步建立多模态连接对（suspend 包装）。
 *
 * 把阻塞的 [LinohEndpoint.connectMultimodal] 调度到 [Dispatchers.IO] 执行。
 *
 * @param host 对端 IP 地址
 * @param port 对端 UDP 端口
 * @param channel 数据通道类型（不应为 [LinohChannel.CONTROL]）
 * @return 新建 [LinohMultimodalConn]；连接失败返回 null
 */
public suspend fun LinohEndpoint.connectMultimodalAsync(
    host: String,
    port: Int,
    channel: LinohChannel,
): LinohMultimodalConn? = withContext(Dispatchers.IO) {
    connectMultimodal(host, port, channel)
}

// ============================================================================
// 2. 轮询循环
// ============================================================================

/**
 * 在指定 [scope] 内启动轮询协程，周期性调用 [LinohEndpoint.poll] 驱动 linoh 内部
 * 事件循环（触发 onConnection / onStream / onConnState / onClose 回调）。
 *
 * linoh 的回调依赖外部周期调用 [LinohEndpoint.poll]，本函数在 [scope] 中按
 * [periodMs] 间隔循环调用，直到协程被取消（`job.cancel()`）或 [LinohEndpoint]
 * 被 [LinohEndpoint.close]。
 *
 * v1.4.2 P1-#1 修复：协程体内增加 try-catch，捕获 [LinohException]（endpoint close 后
 * 调 poll 会抛异常）后安静退出，避免异常向上传播到 scope 根导致整 scope 协程全部取消。
 *
 * 推荐用法：
 * ```
 * val scope = CoroutineScope(Dispatchers.IO)
 * val pollJob = endpoint.pollLoop(scope)
 * // …
 * pollJob.cancel()
 * endpoint.close()
 * ```
 *
 * @param scope 协程作用域（启动一个子协程）
 * @param periodMs 轮询周期，默认 10ms（linoh 推理场景下足够低延迟）
 * @return 协程 Job，调用 `cancel()` 停止轮询
 */
public fun LinohEndpoint.pollLoop(
    scope: CoroutineScope,
    periodMs: Long = 10L,
): Job = scope.launch(Dispatchers.IO) {
    try {
        while (true) {
            ensureActive()
            poll()
            delay(periodMs)
        }
    } catch (e: CancellationException) {
        // 协程正常取消，向下传播
        throw e
    } catch (e: LinohException) {
        // v1.4.2 P1-#1: endpoint 已 close，poll 抛异常时安静退出
        // 不向上传播到 scope，避免级联取消其他协程
    } catch (e: Exception) {
        // 兜底：其他异常也不应破坏 scope
    }
}

// ============================================================================
// 3. 回调 → Flow
// ============================================================================

/**
 * 构造 [LinohEndpoint] 并把 3 个回调转换为 [Flow]。
 *
 * 返回 [FlowEndpoint] 包装，包含：
 * - [FlowEndpoint.endpoint]：[LinohEndpoint] 实例
 * - [FlowEndpoint.connections]：入站连接流（onConnection 回调）
 * - [FlowEndpoint.streams]：入站流流（onStream 回调）
 * - [FlowEndpoint.connStates]：连接状态变化流（onConnState 回调）
 *
 * `onClose` 回调不转换为 Flow（通常作为整体关闭信号，调用方自行处理）。
 *
 * 用法：
 * ```
 * val (endpoint, connFlow, streamFlow, stateFlow) = flowEndpoint(config)
 * val scope = CoroutineScope(Dispatchers.IO)
 * val pollJob = endpoint.pollLoop(scope)
 * scope.launch { connFlow.collect { /* 处理入站连接 */ } }
 * ```
 *
 * @param config Endpoint 配置
 * @param onClose 连接关闭回调（可选，不转换为 Flow）
 */
public fun flowEndpoint(
    config: LinohEndpointConfig,
    onClose: ((Unit) -> Unit)? = null,
): FlowEndpoint {
    val connFlow = MutableSharedFlow<LinohConnection>(extraBufferCapacity = 16)
    val streamFlow = MutableSharedFlow<LinohStream>(extraBufferCapacity = 64)
    val stateFlow = MutableSharedFlow<ConnState>(extraBufferCapacity = 16)

    val endpoint = LinohEndpoint(
        config = config,
        onConnection = { conn -> connFlow.tryEmit(conn) },
        onStream = { stream -> streamFlow.tryEmit(stream) },
        onConnState = { state -> stateFlow.tryEmit(state) },
        onClose = onClose,
    )

    return FlowEndpoint(
        endpoint = endpoint,
        connections = connFlow.asSharedFlow(),
        streams = streamFlow.asSharedFlow(),
        connStates = stateFlow.asSharedFlow(),
    )
}

/** [flowEndpoint] 返回的包装：endpoint 实例 + 3 个回调 Flow。
 *
 * v1.4.2 P1-#3 修复：本类型实现 [AutoCloseable]，调用 [close] 即可释放底层 endpoint
 * 资源（之前需要用户手动 `endpoint.close()`，容易遗漏）。
 */
public data class FlowEndpoint(
    public val endpoint: LinohEndpoint,
    public val connections: Flow<LinohConnection>,
    public val streams: Flow<LinohStream>,
    public val connStates: Flow<ConnState>,
) : AutoCloseable {
    /**
     * 释放底层 [endpoint] 资源。
     *
     * v1.4.2 P1-#3: [FlowEndpoint] 实现 [AutoCloseable]，调用 [close] 即可
     * 释放 endpoint 资源，无需手动 `endpoint.close()`。
     *
     * 调用 [close] 后，3 个 Flow 不再发射事件但仍可 collect（直到已发射事件消费完）。
     */
    override fun close() {
        endpoint.close()
    }
}

// ============================================================================
// 4. 流写入 → suspend 写入
// ============================================================================

/**
 * suspend 版写入：写完后立即 flush，并按 [yieldInterval] 周期 yield 避免阻塞协程。
 *
 * 把大块 [data] 按 [yieldInterval] 分片写入，每片写完 flush 一次并 `delay(0)` 让出
 * 协程执行权，避免长时间占用 IO 线程。
 *
 * @param data 待写入字节
 * @param yieldInterval 每写 [yieldInterval] 字节后 yield 一次，默认 64KB
 * @return 实际写入字节数
 */
public suspend fun LinohStream.writeAwait(data: ByteArray, yieldInterval: Int = 64 * 1024): Long =
    withContext(Dispatchers.IO) {
        var written = 0L
        var offset = 0
        while (offset < data.size) {
            ensureActive()
            val chunkSize = minOf(data.size - offset, yieldInterval)
            val chunkBytes = data.copyOfRange(offset, offset + chunkSize)
            written += write(chunkBytes)
            flush()
            offset += chunkSize
            if (offset < data.size) {
                delay(0)  // yield to other coroutines
            }
        }
        written
    }
