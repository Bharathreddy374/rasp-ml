package com.example.demo.features.probes

import com.example.demo.features.probes.checks.RealChecks
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult

object RiskyContextProbe {

    fun collect(context: Context): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        val cr = context.contentResolver

        // Accessibility (F271 - F273)
        val enabledAccessServices = try {
            Settings.Secure.getString(cr, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES) ?: ""
        } catch (_: Exception) { "" }
        val accessCount = if (enabledAccessServices.isBlank()) 0 else enabledAccessServices.split(":").size

        list.add(
            SignalResult(
                id = "F271",
                name = "accessibility_services_count",
                category = SignalCategory.RISKY_CONTEXT,
                value = "$accessCount active services",
                raw = accessCount,
                riskLevel = if (accessCount > 2) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Enabled Accessibility Services: ${enabledAccessServices.ifEmpty { "None" }}"
            )
        )

        list.add(
            SignalResult(
                id = "F272",
                name = "accessibility_can_gesture",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (accessCount > 0) "Gesture permissions present" else "No gesture services",
                riskLevel = if (accessCount > 0) RiskLevel.INFO else RiskLevel.SAFE,
                details = "Accessibility services with FLAG_REQUEST_TOUCH_EXPLORATION_MODE."
            )
        )

        list.add(RealChecks.get("F273", "accessibility_unknown_pkg", context))

        // Overlays & Screen (F274 - F277)
        val canDrawOverlays = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Settings.canDrawOverlays(context)
        } else {
            false
        }

        list.add(
            SignalResult(
                id = "F274",
                name = "overlay_permission_apps",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (canDrawOverlays) "Granted to app" else "Not granted",
                riskLevel = if (canDrawOverlays) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "SYSTEM_ALERT_WINDOW permission status."
            )
        )

        list.add(RealChecks.get("F275", "overlay_window_present", context))

        list.add(RealChecks.get("F276", "screen_sharing_active", context))

        list.add(RealChecks.get("F277", "media_projection_active", context))

        // Developer settings (F278 - F281)
        val devOptions = try {
            Settings.Global.getInt(cr, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) == 1
        } catch (_: Exception) { false }

        list.add(
            SignalResult(
                id = "F278",
                name = "developer_options_on",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (devOptions) "Enabled" else "Disabled",
                riskLevel = if (devOptions) RiskLevel.INFO else RiskLevel.SAFE,
                details = "Developer options enabled in Android system settings."
            )
        )

        val adbEnabled = try {
            Settings.Global.getInt(cr, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) { false }

        list.add(
            SignalResult(
                id = "F279",
                name = "usb_debugging_on",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (adbEnabled) "Enabled (Active ADB connection)" else "Disabled",
                riskLevel = if (adbEnabled) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "USB debugging / Android Debug Bridge daemon state."
            )
        )

        val adbWifi = try {
            Settings.Global.getInt(cr, "adb_wifi_enabled", 0) == 1
        } catch (_: Exception) { false }

        list.add(
            SignalResult(
                id = "F280",
                name = "adb_wifi_on",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (adbWifi) "Enabled (Wireless debugging)" else "Disabled / Off",
                riskLevel = if (adbWifi) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Wireless ADB daemon over TCP network."
            )
        )

        val unknownSources = try {
            @Suppress("DEPRECATION")
            Settings.Secure.getInt(cr, Settings.Secure.INSTALL_NON_MARKET_APPS, 0) == 1
        } catch (_: Exception) { false }

        list.add(
            SignalResult(
                id = "F281",
                name = "unknown_sources_enabled",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (unknownSources) "Allowed" else "Restricted",
                riskLevel = if (unknownSources) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Global install from unknown sources toggle."
            )
        )

        // Network context (F282)
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        var isVpn = false
        try {
            val network = cm?.activeNetwork
            val caps = cm?.getNetworkCapabilities(network)
            isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ?: false
        } catch (_: Exception) {}

        list.add(
            SignalResult(
                id = "F282",
                name = "vpn_active",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (isVpn) "VPN Active (Tun/Tap interface)" else "Direct Network (No VPN)",
                riskLevel = if (isVpn) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Checks if active network route is handled by a VPN transport."
            )
        )

        // Admin & Notifications & Input (F283 - F285)
        list.add(RealChecks.get("F283", "device_admin_apps", context))

        val notifListeners = try {
            Settings.Secure.getString(cr, "enabled_notification_listeners") ?: ""
        } catch (_: Exception) { "" }
        val notifCount = if (notifListeners.isBlank()) 0 else notifListeners.split(":").size

        list.add(
            SignalResult(
                id = "F284",
                name = "notification_listener_apps",
                category = SignalCategory.RISKY_CONTEXT,
                value = "$notifCount notification listeners",
                riskLevel = if (notifCount > 3) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Apps permitted to intercept incoming notifications and OTPs."
            )
        )

        val defaultIme = try {
            Settings.Secure.getString(cr, Settings.Secure.DEFAULT_INPUT_METHOD) ?: "Standard"
        } catch (_: Exception) { "Standard" }

        val isKnownIme = defaultIme.contains("google", ignoreCase = true) ||
                defaultIme.contains("samsung", ignoreCase = true) ||
                defaultIme.contains("vivo", ignoreCase = true) ||
                defaultIme.contains("oppo", ignoreCase = true) ||
                defaultIme.contains("swiftkey", ignoreCase = true) ||
                defaultIme.contains("gboard", ignoreCase = true)

        list.add(
            SignalResult(
                id = "F285",
                name = "input_method_unknown",
                category = SignalCategory.RISKY_CONTEXT,
                value = if (isKnownIme) "OEM Keyboard" else "Third-party IME ($defaultIme)",
                riskLevel = if (isKnownIme) RiskLevel.SAFE else RiskLevel.INFO,
                details = "Default keyboard IME: $defaultIme"
            )
        )

        return list
    }
}
