package com.linoh.android

/**
 * linoh 多模态数据通道类型。
 *
 * 对应 linoh_c.h 中的 `linoh_multimodal_channel_t` 枚举。
 * 每种通道类型对应独立的 ALPN 标识和独立的数据连接，互不阻塞。
 *
 * 通道类型与 ALPN 映射：
 * - [CONTROL]       → `ctrl/1`       控制面（内部使用，外部不应直接指定）
 * - [LLM_HIDDEN]    → `pp-hidden/1`  LLM hidden_state 逐跳转发（低延迟、AES-256-GCM 强加密）
 * - [IMG_FEATURE]   → `pp-img/1`     图片特征/embedding 传输（大包突发、FEC、Jumbo Frame）
 * - [VIDEO_FEATURE] → `pp-video/1`   视频特征流（持续大流量、Strip 多路径、FEC、Jumbo Frame）
 * - [AUDIO_FEATURE] → `pp-audio/1`   音频流（流式、低延迟）
 * - [FUSION]        → `pp-fusion/1`  多模态融合层
 *
 * **注意**：[CONTROL] 仅供 linoh 内部使用，调用方在 [LinohEndpoint.connectMultimodal]
 * 时不应指定 [CONTROL]，应选择其余数据通道类型。
 *
 * @param value native 枚举值（与 linoh_c.h `LINOH_CHANNEL_*` 常量一致）
 * @param alpn 该通道对应的 ALPN 字符串
 */
public enum class LinohChannel(
    public val value: Int,
    public val alpn: String,
) {
    /** 控制面通道（ALPN=ctrl/1，内部使用，外部不应直接指定）。 */
    CONTROL(value = 0, alpn = "ctrl/1"),

    /** LLM hidden_state 通道（ALPN=pp-hidden/1，低延迟强加密）。 */
    LLM_HIDDEN(value = 1, alpn = "pp-hidden/1"),

    /** 图片特征/embedding 通道（ALPN=pp-img/1，大包突发 + FEC）。 */
    IMG_FEATURE(value = 2, alpn = "pp-img/1"),

    /** 视频特征流通道（ALPN=pp-video/1，持续大流量 + Strip 多路径 + FEC）。 */
    VIDEO_FEATURE(value = 3, alpn = "pp-video/1"),

    /** 音频流通道（ALPN=pp-audio/1，流式低延迟）。 */
    AUDIO_FEATURE(value = 4, alpn = "pp-audio/1"),

    /** 多模态融合层通道（ALPN=pp-fusion/1）。 */
    FUSION(value = 5, alpn = "pp-fusion/1"),
    ;

    public companion object {
        /**
         * 由 native 枚举值反查 [LinohChannel]。
         * 未知值降级为 [CONTROL]（防御性处理，避免 native 层传入未预期值时崩溃）。
         */
        @JvmStatic
        public fun from(value: Int): LinohChannel =
            values().firstOrNull { it.value == value } ?: CONTROL
    }
}
