package com.linoh.android

/**
 * linoh-android 运行时异常。
 *
 * 由 native 层通过 JNI ThrowNew 抛出，封装 C-API 调用失败时的可读错误信息。
 * 属于 unchecked 异常，调用方可选择捕获或上抛。
 */
public class LinohException : RuntimeException {
    public constructor(message: String) : super(message)
    public constructor(message: String, cause: Throwable?) : super(message, cause)
}
