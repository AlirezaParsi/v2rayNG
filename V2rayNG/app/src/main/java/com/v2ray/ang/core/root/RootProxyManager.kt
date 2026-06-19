package com.v2ray.ang.core.root

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.ERunMode
import com.v2ray.ang.util.LogUtil

/**
 * Installs and removes the iptables rules that route system-wide traffic into the
 * core for the root run modes.
 *
 * All rules live in a dedicated chain ([AppConfig.ROOT_IPTABLES_CHAIN]) so teardown is
 * a clean flush. Teardown runs before every setup (to clear stale rules) and on every
 * stop path — leaving a REDIRECT in place after the core dies would break connectivity.
 *
 * Phase 1 implements [ERunMode.REDIRECT] (TCP NAT redirect). [ERunMode.TUN2SOCKS] and
 * [ERunMode.TPROXY] are wired up in later phases.
 */
object RootProxyManager {

    private const val CHAIN = AppConfig.ROOT_IPTABLES_CHAIN

    // Private / local destinations that must never be proxied.
    private val bypassCidrs = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"
    )

    /**
     * Install rules for [mode]. Clears any stale rules first; on failure it tears down
     * again so the device is never left with a half-applied redirect.
     */
    fun start(context: Context, mode: ERunMode): Boolean {
        teardown(context)
        val script = when (mode) {
            ERunMode.REDIRECT -> buildRedirectSetup(context.applicationInfo.uid)
            else -> {
                LogUtil.w(AppConfig.TAG, "RootProxyManager: mode $mode not yet supported")
                return false
            }
        }
        val result = RootShell.runScript(context, "setup_rules.sh", script)
        if (!result.success) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: setup failed, rolling back: ${result.output}")
            teardown(context)
            return false
        }
        LogUtil.i(AppConfig.TAG, "RootProxyManager: $mode rules installed")
        return true
    }

    /** Remove all rules. Safe to call repeatedly. */
    fun stop(context: Context) {
        teardown(context)
        LogUtil.i(AppConfig.TAG, "RootProxyManager: rules removed")
    }

    private fun teardown(context: Context) {
        RootShell.runScript(context, "teardown_rules.sh", buildTeardown())
    }

    private fun buildRedirectSetup(appUid: Int): String {
        val port = AppConfig.PORT_REDIRECT
        return buildString {
            appendLine("set -e")
            appendLine("iptables -t nat -N $CHAIN")
            // Never redirect the app's own traffic (the proxy tunnel itself) -> avoid loop.
            appendLine("iptables -t nat -A $CHAIN -m owner --uid-owner $appUid -j RETURN")
            bypassCidrs.forEach { appendLine("iptables -t nat -A $CHAIN -d $it -j RETURN") }
            // Redirect remaining TCP to the core's dokodemo-door listener.
            appendLine("iptables -t nat -A $CHAIN -p tcp -j REDIRECT --to-ports $port")
            appendLine("iptables -t nat -A OUTPUT -p tcp -j $CHAIN")
        }
    }

    private fun buildTeardown(): String {
        return buildString {
            appendLine("iptables -t nat -D OUTPUT -p tcp -j $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -F $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -X $CHAIN 2>/dev/null || true")
        }
    }
}
