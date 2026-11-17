# linoh-android consumer ProGuard rules
# 保留 JNI 句柄字段（Long handle）和 native 方法

-keepclassmembers class com.linoh.android.** {
    private long handle;
    private volatile boolean closed;
}

-keepclasseswithmembernames class * {
    native <methods>;
}

# 保留 AutoCloseable 接口方法（防止 R8 移除 close()）
-keep class com.linoh.android.** {
    public void close();
    protected void finalize();
}

# 保留回调接口/函数式签名（Kotlin Function1）
-keepclassmembers class com.linoh.android.** {
    kotlin.jvm.functions.Function1<*, *> *;
}
