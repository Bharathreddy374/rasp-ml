package com.example.demo.features.probes.checks

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.system.Os
import android.system.OsConstants
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.NEEDS_NATIVE
import com.example.demo.features.probes.support.NOT_OBSERVABLE
import com.example.demo.features.probes.support.Proc
import com.example.demo.features.probes.support.backendChecked
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import java.io.File
import java.security.MessageDigest

/** Device, root and mount checks (catalogue group 2). */
internal object DeviceChecks {

    fun get(id: String, name: String, context: Context): SignalResult? = when (id) {
        "F025" -> backendChecked(id, name, "Device-reported security patch and OS version compared with the attested values.")
        "F026" -> propsVsBuild(id, name)
        "F034", "F035", "F036" -> unknown(id, name, NOT_OBSERVABLE)
        "F039", "F040" -> unknown(id, name, NEEDS_NATIVE)
        "F044" -> rootManagerCert(id, name, context)
        "F048" -> magiskSocket(id, name)
        "F054" -> setuidBinaries(id, name)
        "F055" -> mountIdGaps(id, name)
        "F061" -> systemBindMounts(id, name)
        "F062" -> unknown(id, name, NOT_OBSERVABLE)
        "F066" -> mountsVsMountinfo(id, name)
        "F072" -> procModules(id, name)
        else -> null
    }

    fun prop(key: String): String = try {
        Class.forName("android.os.SystemProperties").getMethod("get", String::class.java)
            .invoke(null, key) as? String ?: ""
    } catch (_: Exception) {
        ""
    }

    /** Java Build fields vs the system properties they come from; hooks and spoofers change one side. */
    private fun propsVsBuild(id: String, name: String): SignalResult {
        val pairs = listOf(
            "ro.build.id" to Build.ID,
            "ro.build.fingerprint" to Build.FINGERPRINT,
            "ro.build.type" to Build.TYPE,
            "ro.build.tags" to Build.TAGS,
            "ro.build.version.sdk" to Build.VERSION.SDK_INT.toString(),
            "ro.build.version.security_patch" to Build.VERSION.SECURITY_PATCH,
        )
        val compared = pairs.filter { prop(it.first).isNotEmpty() }
        if (compared.isEmpty()) return unknown(id, name, "system properties not readable")
        val diff = compared.filter { (k, v) -> prop(k) != v }.map { it.first }
        return measured(id, name, if (diff.isEmpty()) "Match (${compared.size} fields)" else "Mismatch: ${diff.joinToString()}",
            diff.size, if (diff.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "android.os.Build fields vs the system properties they are read from.")
    }

    private val ROOT_MANAGERS = listOf("com.topjohnwu.magisk", "me.weishu.kernelsu", "me.bmax.apatch", "org.bndeff.apatch")

    @Suppress("DEPRECATION")
    private fun rootManagerCert(id: String, name: String, context: Context): SignalResult {
        val pm = context.packageManager
        for (pkg in ROOT_MANAGERS) {
            val sig = try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo?.apkContentsSigners?.firstOrNull()
                } else {
                    pm.getPackageInfo(pkg, PackageManager.GET_SIGNATURES).signatures?.firstOrNull()
                }
            } catch (_: Exception) {
                null
            } ?: continue
            val hex = MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
            return measured(id, name, "$pkg cert ${hex.take(12)}…", hex.take(32), RiskLevel.INFO,
                "Signing certificate of the installed root manager (identifies official vs repackaged builds).")
        }
        return measured(id, name, "No root manager installed", "none", RiskLevel.SAFE,
            "Signing certificate of an installed root manager, if any.")
    }

    private fun magiskSocket(id: String, name: String): SignalResult {
        val lines = Proc.lines("/proc/net/unix") ?: return unknown(id, name, NOT_OBSERVABLE)
        val hits = lines.count { l -> l.contains("@") && listOf("magisk", "ksu", "apatch", "zygisk").any { l.contains(it, true) } }
        return measured(id, name, if (hits == 0) "None" else "$hits root sockets", hits,
            if (hits == 0) RiskLevel.SAFE else RiskLevel.ALERT, "Abstract UNIX sockets named after root frameworks.")
    }

    private fun setuidBinaries(id: String, name: String): SignalResult {
        val dirs = listOf("/system/bin", "/system/xbin", "/sbin", "/vendor/bin", "/product/bin", "/system_ext/bin")
        var listed = 0
        val found = mutableListOf<String>()
        for (d in dirs) {
            val files = File(d).listFiles() ?: continue
            listed++
            for (f in files) {
                try {
                    if (Os.stat(f.path).st_mode and OsConstants.S_ISUID != 0) found.add(f.path)
                } catch (_: Exception) {
                }
            }
        }
        if (listed == 0) return unknown(id, name, "system binary directories not listable")
        return measured(id, name, if (found.isEmpty()) "0 setuid binaries" else found.take(3).joinToString(), found.size,
            if (found.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "Stock Android has no setuid binaries since 4.3; one usually means a su binary.")
    }

    private fun mountIdGaps(id: String, name: String): SignalResult {
        val ids = Proc.mountInfo()?.map { it.id }?.sorted() ?: return unknown(id, name, "/proc/self/mountinfo not readable")
        val gaps = ids.zipWithNext().count { (a, b) -> b - a > 1 }
        return measured(id, name, "$gaps gaps in ${ids.size} mount IDs", gaps, RiskLevel.INFO,
            "Root hiders unmount entries from the app's namespace, leaving holes in mount IDs (compared per device model).")
    }

    private val SYSTEM_CODE = listOf("/system/lib", "/system/lib64", "/system/bin", "/system/framework",
        "/vendor/lib", "/vendor/lib64", "/vendor/bin", "/system/etc")

    private fun systemBindMounts(id: String, name: String): SignalResult {
        val mounts = Proc.mountInfo() ?: return unknown(id, name, "/proc/self/mountinfo not readable")
        val hits = mounts.filter { m -> SYSTEM_CODE.any { m.mountPoint == it || m.mountPoint.startsWith("$it/") } }
        return measured(id, name, if (hits.isEmpty()) "None" else hits.take(3).joinToString { it.mountPoint }, hits.size,
            if (hits.isEmpty()) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Separate mounts over system code directories or files (module overlays / magic mount).")
    }

    private fun mountsVsMountinfo(id: String, name: String): SignalResult {
        val a = Proc.lines("/proc/self/mounts")?.size
        val b = Proc.mountInfo()?.size
        if (a == null || b == null) return unknown(id, name, "mount tables not readable")
        val diff = a - b
        return measured(id, name, if (diff == 0) "Consistent ($a mounts)" else "mounts=$a mountinfo=$b", diff,
            if (diff == 0) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Two kernel views of the same mount table must agree; a hooked reader shows a difference.")
    }

    private fun procModules(id: String, name: String): SignalResult {
        val lines = Proc.lines("/proc/modules") ?: return unknown(id, name, NOT_OBSERVABLE)
        return measured(id, name, "${lines.size} kernel modules visible", lines.size, RiskLevel.INFO,
            "Kernel modules visible to the app (normally hidden by SELinux).")
    }
}
