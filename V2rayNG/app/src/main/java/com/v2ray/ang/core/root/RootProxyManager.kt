package com.v2ray.ang.core.root

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.ERunMode
import com.v2ray.ang.handler.MmkvManager
import com.v2ray.ang.handler.SettingsManager
import com.v2ray.ang.util.LogUtil
import java.io.File

/**
 * Installs and removes the iptables / ip-rule routing that pushes system-wide traffic
 * into the core for the root run modes.
 *
 * All rules live in dedicated chains ([AppConfig.ROOT_IPTABLES_CHAIN], present in the
 * nat table for REDIRECT and the mangle table for TUN2SOCKS) plus a dedicated routing
 * table / ip rule, so [teardown] is a clean, bounded flush. Teardown runs before every
 * setup (to clear stale rules) and on every stop path — leaving rules behind after the
 * core dies would break the device's connectivity.
 *
 * - [ERunMode.REDIRECT]: TCP NAT redirect into the in-process core's dokodemo inbound.
 * - [ERunMode.TUN2SOCKS]: a bundled `tun2socks` binary (run as root) creates a tun
 *   device and forwards it to the in-process core's SOCKS inbound; marked packets are
 *   routed into the tun. Full TCP + UDP.
 */
object RootProxyManager {

    private const val CHAIN = AppConfig.ROOT_IPTABLES_CHAIN
    private const val TUN = AppConfig.ROOT_TUN_NAME
    private const val TABLE = AppConfig.ROOT_ROUTE_TABLE
    private const val PRIORITY = AppConfig.ROOT_RULE_PRIORITY
    private const val FWMARK = AppConfig.ROOT_FWMARK
    private const val MARK = AppConfig.ROOT_MARK_ROUTE

    // Local / private / multicast destinations that must never be proxied.
    private val bypassCidrs = listOf(
        "0.0.0.0/8", "10.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16",
        "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4"
    )

    fun start(context: Context, mode: ERunMode): Boolean {
        teardown(context)
        val script = when (mode) {
            ERunMode.REDIRECT -> buildRedirectSetup(context.applicationInfo.uid)
            ERunMode.TUN2SOCKS -> buildTun2socksSetup(context) ?: return false
            else -> {
                LogUtil.w(AppConfig.TAG, "RootProxyManager: mode $mode not supported")
                return false
            }
        }
        val result = RootShell.runScript(context, "setup_rules.sh", script)
        if (!result.success) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: setup failed, rolling back:\n${result.output}")
            teardown(context)
            return false
        }
        LogUtil.i(AppConfig.TAG, "RootProxyManager: $mode rules installed")
        return true
    }

    /** Remove all rules and stop helper processes. Safe to call repeatedly. */
    fun stop(context: Context) {
        teardown(context)
        LogUtil.i(AppConfig.TAG, "RootProxyManager: rules removed")
    }

    private fun teardown(context: Context) {
        RootShell.runScript(context, "teardown_rules.sh", buildTeardown(context))
    }

    // ---------------------------------------------------------------- REDIRECT

    private fun buildRedirectSetup(appUid: Int): String {
        val port = AppConfig.PORT_REDIRECT
        return buildString {
            appendLine("iptables -t nat -N $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -F $CHAIN")
            // Never redirect the app's own traffic (the proxy tunnel itself) -> avoid loop.
            appendLine("iptables -t nat -A $CHAIN -m owner --uid-owner $appUid -j RETURN")
            bypassCidrs.forEach { appendLine("iptables -t nat -A $CHAIN -d $it -j RETURN") }
            appendLine("iptables -t nat -A $CHAIN -p tcp -j REDIRECT --to-ports $port")
            appendLine("iptables -t nat -D OUTPUT -p tcp -j $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -A OUTPUT -p tcp -j $CHAIN")
        }
    }

    // --------------------------------------------------------------- TUN2SOCKS

    private fun buildTun2socksSetup(context: Context): String? {
        val bin = File(context.applicationInfo.nativeLibraryDir, AppConfig.ROOT_TUN2SOCKS_BIN)
        if (!bin.exists()) {
            LogUtil.e(AppConfig.TAG, "RootProxyManager: tun2socks binary missing at ${bin.absolutePath}")
            return null
        }
        val appUid = context.applicationInfo.uid
        val port = SettingsManager.getSocksPort()
        val runDir = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR).apply { mkdirs() }
        val pidFile = File(runDir, "tun2socks.pid").absolutePath
        val logFile = File(runDir, "tun2socks.log").absolutePath
        val ipv6 = MmkvManager.decodeSettingsBool(AppConfig.PREF_IPV6_ENABLED)

        return buildString {
            appendLine("set -e")
            appendLine("BIN='${bin.absolutePath}'")
            // tun device node
            appendLine("if [ ! -e /dev/net/tun ]; then mkdir -p /dev/net; mknod /dev/net/tun c 10 200; chmod 666 /dev/net/tun; fi")
            // start tun2socks (its own upstream sockets are fwmarked $FWMARK so they bypass the tun)
            appendLine("nohup \"\$BIN\" -device 'tun://$TUN' -proxy 'socks5://${AppConfig.LOOPBACK}:$port' -fwmark $FWMARK >'$logFile' 2>&1 &")
            appendLine("echo \$! > '$pidFile'")
            // wait for the interface to appear
            appendLine("i=0; while [ \$i -lt 20 ]; do ip link show $TUN >/dev/null 2>&1 && break; sleep 0.3; i=\$((i+1)); done")
            appendLine("ip link show $TUN >/dev/null 2>&1 || { echo 'tun device did not come up'; exit 1; }")
            // relax reverse-path filtering for the tun
            appendLine("echo 0 > /proc/sys/net/ipv4/conf/$TUN/rp_filter 2>/dev/null || true")
            appendLine("echo 0 > /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || true")
            // address + default route in a dedicated table
            appendLine("ip addr add ${AppConfig.ROOT_TUN_ADDR_V4} dev $TUN 2>/dev/null || true")
            appendLine("ip link set dev $TUN up")
            appendLine("ip route replace default dev $TUN table $TABLE")
            appendLine("ip rule add fwmark $MARK table $TABLE priority $PRIORITY")
            // mark which packets go into the tun
            append(buildMangleMarking("iptables", appUid))
            if (ipv6) {
                // IPv6 is best-effort: never fail the (working) IPv4 setup over it.
                appendLine("set +e")
                appendLine("ip -6 addr add ${AppConfig.ROOT_TUN_ADDR_V6} dev $TUN 2>/dev/null || true")
                appendLine("ip -6 route replace default dev $TUN table $TABLE 2>/dev/null || true")
                appendLine("ip -6 rule add fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
                append(buildMangleMarking("ip6tables", appUid))
            }
        }
    }

    /** mangle OUTPUT marking chain shared by the ipv4/ipv6 variants. */
    private fun buildMangleMarking(cmd: String, appUid: Int): String {
        return buildString {
            appendLine("$cmd -t mangle -N $CHAIN 2>/dev/null || true")
            appendLine("$cmd -t mangle -F $CHAIN")
            // tun2socks' own upstream traffic and the app's own core traffic must not loop.
            appendLine("$cmd -t mangle -A $CHAIN -m mark --mark $FWMARK -j RETURN")
            appendLine("$cmd -t mangle -A $CHAIN -m owner --uid-owner $appUid -j RETURN")
            bypassCidrs.forEach { appendLine("$cmd -t mangle -A $CHAIN -d $it -j RETURN") }
            // system services + regular apps -> push into the tun via fwmark routing
            appendLine("$cmd -t mangle -A $CHAIN -m owner --uid-owner 1000 -j MARK --set-xmark $MARK")
            appendLine("$cmd -t mangle -A $CHAIN -m owner --uid-owner 9999-2147483647 -j MARK --set-xmark $MARK")
            appendLine("$cmd -t mangle -D OUTPUT -j $CHAIN 2>/dev/null || true")
            appendLine("$cmd -t mangle -A OUTPUT -j $CHAIN")
        }
    }

    // ---------------------------------------------------------------- teardown

    private fun buildTeardown(context: Context): String {
        val runDir = File(context.filesDir, AppConfig.ROOT_RUNTIME_DIR)
        val pidFile = File(runDir, "tun2socks.pid").absolutePath
        return buildString {
            // nat (REDIRECT)
            appendLine("iptables -t nat -D OUTPUT -p tcp -j $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -F $CHAIN 2>/dev/null || true")
            appendLine("iptables -t nat -X $CHAIN 2>/dev/null || true")
            // mangle (TUN2SOCKS), both families
            for (cmd in listOf("iptables", "ip6tables")) {
                appendLine("$cmd -t mangle -D OUTPUT -j $CHAIN 2>/dev/null || true")
                appendLine("$cmd -t mangle -F $CHAIN 2>/dev/null || true")
                appendLine("$cmd -t mangle -X $CHAIN 2>/dev/null || true")
            }
            // routing rule + table
            appendLine("ip rule del fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
            appendLine("ip -6 rule del fwmark $MARK table $TABLE priority $PRIORITY 2>/dev/null || true")
            appendLine("ip route flush table $TABLE 2>/dev/null || true")
            appendLine("ip -6 route flush table $TABLE 2>/dev/null || true")
            // tun device down + helper process
            appendLine("ip link set dev $TUN down 2>/dev/null || true")
            appendLine("[ -f '$pidFile' ] && kill \$(cat '$pidFile') 2>/dev/null || true")
            appendLine("rm -f '$pidFile'")
        }
    }
}
