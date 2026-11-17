/*
 * linoh Android Sample — Foreground Service 示例
 *
 * 本文件为示例代码，不打包到 AAR，仅供集成方参考。
 *
 * 演示内容：
 * 1. 在 Foreground Service 中运行 linoh endpoint（长连接场景）
 * 2. 用 kotlinx-coroutines 周期 poll + 异步 connect
 * 3. 用 Flow 收集入站连接/流/状态变化
 * 4. 通知栏展示连接状态
 *
 * 集成步骤：
 * 1. AndroidManifest.xml 声明 FOREGROUND_SERVICE + POST_NOTIFICATIONS 权限
 * 2. AndroidManifest.xml 声明本 Service
 * 3. 在 Activity 中 startForegroundService(Intent(this, LinohService::class.java))
 *
 * AndroidManifest.xml 片段：
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
 * <uses-permission android:name="android.permission.FOREGROUND_SERVICE_DATA_SYNC" />
 * <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
 * <service
 *     android:name=".LinohService"
 *     android:foregroundServiceType="dataSync"
 *     android:exported="false" />
 */

package com.linoh.android.sample

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.linoh.android.ConnState
import com.linoh.android.LinohChannel
import com.linoh.android.LinohEndpointConfig
import com.linoh.android.flowEndpoint
import com.linoh.android.pollLoop
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import java.security.SecureRandom

/**
 * linoh Foreground Service 示例。
 *
 * 启动后：
 * 1. 创建 linoh endpoint（随机密钥 + 默认端口）
 * 2. 启动 poll 循环协程驱动回调
 * 3. 用 Flow 收集连接状态变化并更新通知
 * 4. 主动连接指定 host:port（通过 Intent extra 传入）
 *
 * Intent extras：
 * - EXTRA_HOST: String，对端 IP
 * - EXTRA_PORT: Int，对端端口
 * - EXTRA_CHANNEL: String，数据通道（"LLM_HIDDEN"/"IMG_FEATURE"/...），可选
 */
class LinohService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var pollJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, buildNotification("linoh 启动中…"))

        // 启动 linoh endpoint
        val secretKey = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val config = LinohEndpointConfig(
            secretKey = secretKey,
            alpn = "ctrl/1",
            udpPort = 0,  // 系统分配端口
        )

        // flowEndpoint 工厂构造 endpoint + 3 个 Flow
        val flowEndpoint = flowEndpoint(config)
        val ep = flowEndpoint.endpoint
        endpoint = ep  // 保留引用供 onDestroy 释放

        // 1) 启动 poll 循环协程（驱动 linoh 内部事件循环 + 回调触发）
        pollJob = ep.pollLoop(scope, periodMs = 10L)

        // 2) 收集连接状态变化，更新通知
        scope.launch {
            flowEndpoint.connStates.collect { state ->
                updateNotification("conn state: ${state.name}")
            }
        }

        // 3) 收集入站连接
        scope.launch {
            flowEndpoint.connections.collect { conn ->
                updateNotification("inbound conn: peer=${conn.peerId().take(8).toHex()}")
            }
        }

        // 4) 收集入站流
        scope.launch {
            flowEndpoint.streams.collect { /* stream 可读取数据 */ }
        }

        // 5) 主动连接（如果 Intent 带了 host/port）
        val host = intent?.getStringExtra(EXTRA_HOST)
        val port = intent?.getIntExtra(EXTRA_PORT, 0) ?: 0
        val channelStr = intent?.getStringExtra(EXTRA_CHANNEL) ?: "LLM_HIDDEN"
        if (host != null && port > 0) {
            scope.launch {
                val channel = LinohChannel.valueOf(channelStr)
                val pair = endpoint.connectMultimodalAsync(host, port, channel)
                if (pair != null) {
                    updateNotification("multimodal connected: ${pair.dataChannel().alpn}")
                } else {
                    updateNotification("multimodal connect failed")
                }
            }
        }

        return START_STICKY
    }

    override fun onDestroy() {
        // v1.4.2 P1-#2 修复：正确的关闭顺序
        //   1) 先 cancel pollJob（停止新的 poll 调用）
        //   2) close endpoint（释放 native 资源、停止内部线程）
        //   3) cancel scope（停止其他协程）
        // 旧版本只 cancel scope，endpoint 句柄依赖 GC 释放，会导致 native 资源泄漏
        // 且 cancel 过程中 poll 协程可能访问已 close 的 endpoint 引发 UAF
        pollJob?.cancel()
        pollJob = null
        endpoint?.close()
        endpoint = null
        scope.cancel()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // --- 通知辅助 ---

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "linoh service",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "linoh P2P QUIC 长连接"
            }
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("linoh service")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .build()

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }

    companion object {
        private const val CHANNEL_ID = "linoh_service_channel"
        private const val NOTIFICATION_ID = 1001

        const val EXTRA_HOST = "host"
        const val EXTRA_PORT = "port"
        const val EXTRA_CHANNEL = "channel"
    }
}

/**
 * 状态枚举到字符串的辅助扩展（仅示例用）。
 */
private fun ConnState.name(): String = this.name
