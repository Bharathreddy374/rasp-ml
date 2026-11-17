package com.example.demo.features.probes.checks

import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.hardware.display.DisplayManager
import android.provider.Settings
import android.view.Display
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.NEEDS_COHORT
import com.example.demo.features.probes.support.NEEDS_NATIVE
import com.example.demo.features.probes.support.NEEDS_UI
import com.example.demo.features.probes.support.NOT_OBSERVABLE
import com.example.demo.features.probes.support.Proc
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import kotlin.math.floor
import kotlin.math.ln
import kotlin.math.round

/** Memory / procfs (group 5) and risky-context (group 8) checks. */
internal object ProcContextChecks {

    fun get(id: String, name: String, context: Context?): SignalResult? = when (id) {
        "F182" -> regionEntropy(id, name)
        "F183", "F197" -> unknown(id, name, NEEDS_COHORT)
        "F194" -> threadNameEntropy(id, name)
        "F198" -> unknown(id, name, NEEDS_NATIVE)
        "F199" -> realtimeThreads(id, name)
        "F273" -> context?.let { accessibilityNonSystem(id, name, it) }
        "F275" -> unknown(id, name, NEEDS_UI)
        "F276" -> context?.let { secondaryDisplays(id, name, it) }
        "F277" -> unknown(id, name, NOT_OBSERVABLE)
        "F283" -> context?.let { deviceAdmins(id, name, it) }
        else -> null
    }

    private fun r3(x: Double) = round(x * 1000) / 1000

    private fun regionEntropy(id: String, name: String): SignalResult {
        val maps = Proc.maps() ?: return unknown(id, name, "/proc/self/maps not readable")
        val buckets = maps.filter { it.size > 0 }.map { floor(ln(it.size.toDouble()) / ln(2.0)).toInt() }
        val h = r3(Proc.entropy(buckets))
        return measured(id, name, "$h bits over ${maps.size} regions", h, RiskLevel.INFO,
            "Entropy of power-of-two region sizes; injected agents change the shape (compared per device model).")
    }

    private fun threadNameEntropy(id: String, name: String): SignalResult {
        val tasks = Proc.tasks()
        if (tasks.isEmpty()) return unknown(id, name, "thread list not readable")
        val h = r3(Proc.entropy(tasks.map { it.name.trimEnd { c -> c.isDigit() } }))
        return measured(id, name, "$h bits over ${tasks.size} threads", h, RiskLevel.INFO,
            "Entropy of thread names (digits stripped); injected runtimes add unusual thread families.")
    }

    private fun realtimeThreads(id: String, name: String): SignalResult {
        val tasks = Proc.tasks()
        if (tasks.isEmpty()) return unknown(id, name, "thread list not readable")
        val rt = tasks.count { it.policy == 1 || it.policy == 2 }
        return measured(id, name, "$rt real-time threads of ${tasks.size}", rt, RiskLevel.INFO,
            "Threads with SCHED_FIFO / SCHED_RR policy in this process.")
    }

    private fun accessibilityNonSystem(id: String, name: String, context: Context): SignalResult {
        val enabled = Settings.Secure.getString(context.contentResolver, Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES)
            ?.split(':')?.mapNotNull { it.substringBefore('/').takeIf { p -> p.isNotBlank() } }?.distinct()
            ?: emptyList()
        val pm = context.packageManager
        val thirdParty = enabled.filter { pkg ->
            try {
                pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM == 0
            } catch (_: Exception) {
                true // not resolvable: treat as unknown third party
            }
        }
        return measured(id, name, if (thirdParty.isEmpty()) "None" else thirdParty.joinToString(), thirdParty.size,
            if (thirdParty.isEmpty()) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Enabled accessibility services from non-system apps (banking trojans drive the UI this way).")
    }

    private fun secondaryDisplays(id: String, name: String, context: Context): SignalResult {
        val dm = context.getSystemService(Context.DISPLAY_SERVICE) as? DisplayManager
            ?: return unknown(id, name, "display service unavailable")
        val extra = dm.displays.filter { it.displayId != Display.DEFAULT_DISPLAY }
        return measured(id, name, if (extra.isEmpty()) "Only the built-in display" else extra.joinToString { it.name }, extra.size,
            if (extra.isEmpty()) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Extra displays visible to the app (casting, mirroring, public virtual displays).")
    }

    private fun deviceAdmins(id: String, name: String, context: Context): SignalResult {
        val dpm = context.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
            ?: return unknown(id, name, "device policy service unavailable")
        val pm = context.packageManager
        val third = (dpm.activeAdmins ?: emptyList()).map { it.packageName }.distinct().filter { pkg ->
            try {
                pm.getApplicationInfo(pkg, 0).flags and ApplicationInfo.FLAG_SYSTEM == 0
            } catch (_: Exception) {
                true
            }
        }
        return measured(id, name, if (third.isEmpty()) "None" else third.joinToString(), third.size,
            if (third.isEmpty()) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Active device administrators from non-system apps (malware uses this to resist removal; MDM is legitimate).")
    }
}
