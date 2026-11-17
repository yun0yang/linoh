/*
 * linoh Android Sample — MainActivity 示例
 *
 * 本文件为示例代码，不打包到 AAR，仅供集成方参考。
 *
 * 演示内容：
 * 1. 在 Activity 中启动 LinohService（Foreground Service）
 * 2. 通过 Intent extra 传入对端 host/port/channel
 * 3. 申请 POST_NOTIFICATIONS 权限（Android 13+）
 *
 * 集成方需在 build.gradle 中额外添加 androidx.core 依赖：
 *   implementation("androidx.core:core-ktx:1.13.1")
 */

package com.linoh.android.sample

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import androidx.activity.ComponentActivity
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat

/**
 * linoh Sample Activity：输入对端 host/port/channel，点击启动 Foreground Service。
 *
 * 布局示例（res/layout/activity_main.xml）：
 * <LinearLayout android:orientation="vertical" ...>
 *     <EditText android:id="@+id/hostEt" android:hint="host" />
 *     <EditText android:id="@+id/portEt" android:hint="port" android:inputType="number" />
 *     <Spinner android:id="@+id/channelSpinner" />
 *     <Button android:id="@+id/startBtn" android:text="启动 linoh" />
 * </LinearLayout>
 */
class MainActivity : ComponentActivity() {

    private lateinit var hostEt: EditText
    private lateinit var portEt: EditText
    private lateinit var startBtn: Button

    private val requestNotificationPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { /* granted or not */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // setContentView(R.layout.activity_main)
        // hostEt = findViewById(R.id.hostEt)
        // portEt = findViewById(R.id.portEt)
        // startBtn = findViewById(R.id.startBtn)

        // Android 13+ 申请通知权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) {
                requestNotificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        startBtn.setOnClickListener {
            val host = hostEt.text.toString().trim().ifEmpty { "127.0.0.1" }
            val port = portEt.text.toString().trim().toIntOrNull() ?: 9999
            val channel = "LLM_HIDDEN"  // 从 spinner 读取

            val intent = Intent(this, LinohService::class.java).apply {
                putExtra(LinohService.EXTRA_HOST, host)
                putExtra(LinohService.EXTRA_PORT, port)
                putExtra(LinohService.EXTRA_CHANNEL, channel)
            }
            ContextCompat.startForegroundService(this, intent)
        }
    }
}
