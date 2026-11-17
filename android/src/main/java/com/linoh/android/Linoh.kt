package com.linoh.android

/**
 * linoh-android 入口。
 *
 * 加载 native 库 [liblinoh_jni.so]，提供版本号查询。
 *
 * 使用前请确保宿主 App 已加载 c++_shared（linoh_jni 链接的是 shared STL）。
 * 通常由 AGP 自动打包 libc++_shared.so 到 APK；若需手动加载：
 * ```
 * System.loadLibrary("c++_shared")
 * System.loadLibrary("linoh_jni")
 * ```
 */
public object Linoh {

    @Volatile
    private var loaded: Boolean = false

    /**
     * 加载 linoh_jni native 库。多次调用幂等。
     *
     * @throws LinohException 加载失败
     */
    @JvmStatic
    @Synchronized
    public fun ensureLoaded() {
        if (loaded) return
        try {
            System.loadLibrary("c++_shared")
        } catch (e: UnsatisfiedLinkError) {
            // 部分设备 c++_shared 由系统提供，忽略
        }
        try {
            System.loadLibrary("linoh_jni")
        } catch (e: UnsatisfiedLinkError) {
            throw LinohException("Failed to load liblinoh_jni.so: ${e.message}", e)
        }
        loaded = true
    }

    /**
     * 获取 linoh native 库版本号字符串（如 "1.4.0"）。
     *
     * @throws LinohException native 库未加载
     */
    @JvmStatic
    public fun nativeVersion(): String {
        ensureLoaded()
        return doNativeVersion()
    }

    private external fun doNativeVersion(): String
}
