package com.example.demo.features.probes.checks

import android.app.Application
import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.ApkInspector
import com.example.demo.features.probes.support.NEEDS_COHORT
import com.example.demo.features.probes.support.NOT_OBSERVABLE
import com.example.demo.features.probes.support.Proc
import com.example.demo.features.probes.support.backendChecked
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import java.security.MessageDigest

/** App integrity (catalogue group 3): signing, APK contents, process and class loaders. */
internal object AppChecks {

    private const val MANIFEST = "Compared on the backend with the release build manifest (tools/apk_manifest.py)."

    fun get(id: String, name: String, context: Context): SignalResult? = when (id) {
        "F078" -> certTwoSources(id, name, context)
        "F079" -> apk(id, name, context) { f ->
            val s = buildList {
                if (f.v1Signed) add("v1")
                f.schemes.sorted().forEach { add(if (it == 31) "v3.1" else "v$it") }
            }.joinToString("+").ifEmpty { "none" }
            val modern = f.schemes.any { it in setOf(2, 3, 31) }
            measured(id, name, s, s, if (modern) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                "Signature schemes found in the installed APK (v2+ is required for this app's target SDK).")
        }
        "F081" -> backendChecked(id, name, "Signing digest compared with expected_cert_sha256 on the backend.")
        "F083" -> apk(id, name, context) { f ->
            measured(id, name, if (f.sigBlockPresent) "Present" else "Missing", f.sigBlockPresent,
                if (f.sigBlockPresent) RiskLevel.SAFE else RiskLevel.ALERT,
                "APK Signing Block ('APK Sig Block 42') read directly from the APK file.")
        }
        "F084" -> apk(id, name, context) { measured(id, name, "DEX digest ${it.dexDigest.take(12)}…", it.dexDigest, details = MANIFEST) }
        "F085" -> apk(id, name, context) { measured(id, name, "${it.dexCount} dex files", it.dexCount, details = MANIFEST) }
        "F086" -> apk(id, name, context) { measured(id, name, "Native lib digest ${it.soDigest.take(12)}…", it.soDigest, details = MANIFEST) }
        "F087" -> apk(id, name, context) { measured(id, name, "${it.soCount} native libs", it.soCount, details = MANIFEST) }
        "F088" -> backendChecked(id, name, "Derived from the native-library digest (F086) against the release manifest.")
        "F090" -> apk(id, name, context) { measured(id, name, "crc ${it.arscCrc ?: "missing"}", it.arscCrc ?: "missing", details = MANIFEST) }
        "F091" -> apk(id, name, context) { measured(id, name, "crc ${it.manifestCrc ?: "missing"}", it.manifestCrc ?: "missing", details = MANIFEST) }
        "F092" -> apk(id, name, context) { measured(id, name, "Assets digest ${it.assetsDigest.take(12)}…", it.assetsDigest, details = MANIFEST) }
        "F093" -> unknown(id, name, NEEDS_COHORT)
        "F103" -> unknown(id, name, NOT_OBSERVABLE)
        "F109" -> processName(id, name, context)
        "F110" -> classLoaders(id, name, context, inMemoryOnly = false)
        "F111" -> classLoaders(id, name, context, inMemoryOnly = true)
        "F115" -> untrustedLibs(id, name, context)
        else -> null
    }

    private fun apk(id: String, name: String, context: Context, f: (ApkInspector.Facts) -> SignalResult): SignalResult =
        try {
            f(ApkInspector.inspect(context.applicationInfo.sourceDir))
        } catch (_: Exception) {
            unknown(id, name, "the installed APK could not be read")
        }

    private fun sha256(sig: Signature): String =
        MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }

    @Suppress("DEPRECATION")
    private fun certTwoSources(id: String, name: String, context: Context): SignalResult {
        val pm = context.packageManager
        return try {
            val installed: Set<String>
            val onDisk: Set<String>
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                installed = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                    .signingInfo?.apkContentsSigners?.map(::sha256)?.toSet() ?: emptySet()
                onDisk = pm.getPackageArchiveInfo(context.applicationInfo.sourceDir, PackageManager.GET_SIGNING_CERTIFICATES)
                    ?.signingInfo?.apkContentsSigners?.map(::sha256)?.toSet() ?: emptySet()
            } else {
                installed = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                    .signatures?.map(::sha256)?.toSet() ?: emptySet()
                onDisk = pm.getPackageArchiveInfo(context.applicationInfo.sourceDir, PackageManager.GET_SIGNATURES)
                    ?.signatures?.map(::sha256)?.toSet() ?: emptySet()
            }
            if (installed.isEmpty() || onDisk.isEmpty()) return unknown(id, name, "a signing certificate source was empty")
            val mismatch = installed != onDisk
            measured(id, name, if (mismatch) "Mismatch" else "Match", mismatch,
                if (mismatch) RiskLevel.ALERT else RiskLevel.SAFE,
                "Signing certificate from PackageManager vs parsed from the APK file on disk.")
        } catch (_: Exception) {
            unknown(id, name, "the APK could not be parsed for certificates")
        }
    }

    private fun processName(id: String, name: String, context: Context): SignalResult {
        val cmdline = Proc.read("/proc/self/cmdline")?.substringBefore('\u0000')?.trim()
        val api = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) Application.getProcessName() else null
        val pkg = context.packageName
        val names = listOfNotNull(cmdline, api).filter { it.isNotEmpty() }
        if (names.isEmpty()) return unknown(id, name, "process name not readable")
        val mismatch = names.distinct().size > 1 || names.any { it != pkg && !it.startsWith("$pkg:") }
        return measured(id, name, if (mismatch) "Mismatch (${names.distinct().joinToString(" / ")})" else "Match",
            mismatch, if (mismatch) RiskLevel.ALERT else RiskLevel.SAFE,
            "Process name from /proc/self/cmdline and Application.getProcessName() vs the package name " +
                "(virtual-app hosts run us under their own process).")
    }

    private val STANDARD_LOADERS = setOf(
        "dalvik.system.PathClassLoader", "java.lang.BootClassLoader", "dalvik.system.DelegateLastClassLoader",
    )

    private fun classLoaders(id: String, name: String, context: Context, inMemoryOnly: Boolean): SignalResult {
        val chain = generateSequence(context.classLoader) { it.parent }.map { it.javaClass.name }.toList()
        val hits = chain.filter {
            if (inMemoryOnly) it == "dalvik.system.InMemoryDexClassLoader" else it !in STANDARD_LOADERS
        }
        return measured(id, name,
            if (hits.isEmpty()) "None" else hits.joinToString(), hits.size,
            if (hits.isEmpty()) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
            "Non-standard class loaders in this app's loader chain (${chain.size} loaders).")
    }

    private fun untrustedLibs(id: String, name: String, context: Context): SignalResult {
        val maps = Proc.maps() ?: return unknown(id, name, "/proc/self/maps not readable")
        val own = setOf(context.applicationInfo.dataDir, "/data/user/0/${context.packageName}", "/data/data/${context.packageName}")
        val bad = maps.map { it.path }.filter { p ->
            val so = p.contains(".so")
            so && (p.startsWith("/data/local/tmp") || p.startsWith("/sdcard") || p.startsWith("/storage") ||
                p.startsWith("/memfd:") || p.endsWith("(deleted)") ||
                ((p.startsWith("/data/data/") || p.startsWith("/data/user/")) && own.none { p.startsWith(it) }))
        }.distinct()
        return measured(id, name, if (bad.isEmpty()) "None" else bad.take(3).joinToString(), bad.size,
            if (bad.isEmpty()) RiskLevel.SAFE else RiskLevel.ALERT,
            "Native libraries mapped from writable or foreign locations (injected code).")
    }
}
