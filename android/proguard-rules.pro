# linoh-android 自身 R8/ProGuard 规则（release 构建使用）
# 消费者规则见 consumer-rules.pro

-keepattributes Signature, Exceptions, InnerClasses, EnclosingMethod
-keepattributes RuntimeVisibleAnnotations, RuntimeVisibleParameterAnnotations

# JNI native 方法保留（与 consumer-rules.pro 一致）
-keepclasseswithmembernames class * {
    native <methods>;
}
