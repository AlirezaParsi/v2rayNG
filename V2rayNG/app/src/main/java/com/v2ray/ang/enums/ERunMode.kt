package com.v2ray.ang.enums

import com.v2ray.ang.AppConfig

/**
 * The way the core routes system traffic.
 *
 * [VPN] and [PROXY_ONLY] keep the historical behavior and need no root.
 * [REDIRECT], [TUN2SOCKS] and [TPROXY] are root-only system-wide modes that do
 * not use Android [android.net.VpnService].
 *
 * The string [prefValue] is what gets persisted in [AppConfig.PREF_MODE]; the legacy
 * values "VPN" and "Proxy only" are preserved so existing installs keep working.
 */
enum class ERunMode(val prefValue: String, val needsRoot: Boolean) {
    VPN(AppConfig.MODE_VPN, false),
    PROXY_ONLY(AppConfig.MODE_PROXY_ONLY, false),
    REDIRECT(AppConfig.MODE_REDIRECT, true),
    TUN2SOCKS(AppConfig.MODE_TUN2SOCKS, true),
    TPROXY(AppConfig.MODE_TPROXY, true);

    /**
     * Whether the traffic is served by the in-process gomobile core.
     * Only [TPROXY] runs a separate root xray binary instead.
     */
    fun usesInProcessCore(): Boolean = this != TPROXY

    companion object {
        fun fromPref(value: String?): ERunMode {
            if (value.isNullOrEmpty()) return VPN
            return entries.firstOrNull { it.prefValue == value } ?: VPN
        }
    }
}
