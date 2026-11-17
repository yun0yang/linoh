package com.linoh.android

/**
 * linoh Endpoint 配置。
 *
 * 与 linoh_c.h 中 `linoh_endpoint_config_t` 对应（不含 user_data，user_data 由 LinohEndpoint 内部管理）。
 *
 * @property secretKey Ed25519 私钥，长度必须为 32 字节
 * @property alpn ALPN 协议标识，如 "ctrl/1"、"pp-hidden/1"
 * @property udpPort 本地 UDP 监听端口，0 表示由系统随机分配
 */
public data class LinohEndpointConfig(
    public val secretKey: ByteArray,
    public val alpn: String,
    public val udpPort: Int = 0,
) {
    init {
        require(secretKey.size == 32) { "secretKey must be 32 bytes, got ${secretKey.size}" }
        require(alpn.isNotEmpty()) { "alpn must not be empty" }
        require(udpPort in 0..65535) { "udpPort out of range: $udpPort" }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LinohEndpointConfig) return false
        return alpn == other.alpn &&
            udpPort == other.udpPort &&
            secretKey.contentEquals(other.secretKey)
    }

    override fun hashCode(): Int {
        var result = secretKey.contentHashCode()
        result = 31 * result + alpn.hashCode()
        result = 31 * result + udpPort
        return result
    }
}
