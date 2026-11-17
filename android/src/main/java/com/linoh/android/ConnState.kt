package com.linoh.android

/**
 * linoh 连接状态。
 *
 * 与 linoh_c.h 中 `linoh_conn_state_t` 一一对应。
 */
public enum class ConnState(public val value: Int) {
    INITIAL(0),
    HANDSHAKE(1),
    ESTABLISHED(2),
    CLOSING(3),
    DRAINING(4),
    CLOSED(5);

    public companion object {
        /**
         * 由 native 整数值构造 [ConnState]。
         * 未知值返回 [CLOSED] 作为安全降级。
         */
        @JvmStatic
        public fun from(value: Int): ConnState {
            return entries.firstOrNull { it.value == value } ?: CLOSED
        }
    }
}
