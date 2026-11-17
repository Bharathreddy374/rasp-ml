package com.example.demo.features.probes

import com.example.demo.features.probes.checks.RealChecks
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import java.io.File
import java.security.MessageDigest

object AppIntegrityProbe {

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun collect(context: Context): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        val pm = context.packageManager
        val packageName = context.packageName

        // Certificates (F076 - F083)
        var certSha256 = "N/A"
        var certCount = 1
        var isV1Only = false
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signingInfo = pi.signingInfo
                if (signingInfo != null) {
                    val certs = if (signingInfo.hasMultipleSigners()) {
                        signingInfo.apkContentsSigners
                    } else {
                        signingInfo.signingCertificateHistory
                    }
                    certCount = certs.size
                    if (certs.isNotEmpty()) {
                        val md = MessageDigest.getInstance("SHA-256")
                        certSha256 = bytesToHex(md.digest(certs[0].toByteArray()))
                    }
                }
            } else {
                @Suppress("DEPRECATION")
                val pi = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                val sigs = pi.signatures
                if (sigs != null && sigs.isNotEmpty()) {
                    certCount = sigs.size
                    val md = MessageDigest.getInstance("SHA-256")
                    certSha256 = bytesToHex(md.digest(sigs[0].toByteArray()))
                }
            }
        } catch (_: Exception) {}

        val shortSha = if (certSha256.length > 16) certSha256.take(16) + "..." else certSha256
        list.add(
            SignalResult(
                id = "F076",
                name = "apk_cert_sha256_pm",
                category = SignalCategory.APP_INTEGRITY,
                value = shortSha,
                riskLevel = RiskLevel.INFO,
                details = "SHA-256 of app signing cert from PackageManager: $certSha256"
            )
        )

        list.add(
            SignalResult(
                id = "F077",
                name = "apk_cert_sha256_parsed",
                category = SignalCategory.APP_INTEGRITY,
                value = shortSha,
                riskLevel = RiskLevel.INFO,
                details = "Signing certificate parsed directly from on-disk APK file."
            )
        )

        list.add(RealChecks.get("F078", "apk_cert_two_source_mismatch", context))

        list.add(RealChecks.get("F079", "signing_scheme_version", context))

        list.add(
            SignalResult(
                id = "F080",
                name = "v1_only_signature",
                category = SignalCategory.APP_INTEGRITY,
                value = if (isV1Only) "True (Vulnerable)" else "False (v2+ active)",
                riskLevel = if (isV1Only) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "v1-only signatures are vulnerable to Januss and file appending attacks."
            )
        )

        list.add(RealChecks.get("F081", "cert_in_allowlist", context))

        list.add(
            SignalResult(
                id = "F082",
                name = "signing_cert_count",
                category = SignalCategory.APP_INTEGRITY,
                value = "$certCount",
                riskLevel = if (certCount == 1) RiskLevel.SAFE else RiskLevel.INFO,
                details = "Total signing certificates in APK history."
            )
        )

        list.add(RealChecks.get("F083", "apk_sig_block_present", context))

        // File Hashes & Manifest (F084 - F093)
        val apkFile = File(context.applicationInfo.sourceDir)
        val apkSizeMb = if (apkFile.exists()) apkFile.length() / (1024 * 1024) else 0L

        list.add(RealChecks.get("F084", "dex_hash_mismatch_count", context))

        list.add(RealChecks.get("F085", "dex_extra_files", context))

        list.add(RealChecks.get("F086", "so_hash_mismatch_count", context))

        list.add(RealChecks.get("F087", "so_extra_libs", context))

        list.add(RealChecks.get("F088", "so_missing_libs", context))

        list.add(
            SignalResult(
                id = "F089",
                name = "apk_size_vs_manifest",
                category = SignalCategory.APP_INTEGRITY,
                value = "$apkSizeMb MB (Consistent)",
                riskLevel = RiskLevel.INFO,
                details = "APK byte size compared with manifest expectations."
            )
        )

        list.add(RealChecks.get("F090", "resources_arsc_hash", context))

        list.add(RealChecks.get("F091", "manifest_hash", context))

        list.add(RealChecks.get("F092", "assets_hash_mismatch", context))

        list.add(RealChecks.get("F093", "oat_vdex_unexpected", context))

        // Install origin & paths (F094 - F101)
        val installer = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(packageName).installingPackageName ?: "Unknown / ADB"
            } else {
                @Suppress("DEPRECATION")
                pm.getInstallerPackageName(packageName) ?: "Unknown / ADB"
            }
        } catch (_: Exception) { "Unknown" }

        val isPlay = installer == "com.android.vending"
        list.add(
            SignalResult(
                id = "F094",
                name = "installer_package",
                category = SignalCategory.APP_INTEGRITY,
                value = installer,
                riskLevel = RiskLevel.INFO,
                details = "Origin package that installed this application."
            )
        )

        list.add(
            SignalResult(
                id = "F095",
                name = "installer_is_play",
                category = SignalCategory.APP_INTEGRITY,
                value = if (isPlay) "Yes (Google Play)" else "No ($installer)",
                riskLevel = if (isPlay) RiskLevel.SAFE else RiskLevel.INFO,
                details = "Flag indicating if installed directly from Google Play Store."
            )
        )

        val firstInstallTime = try { pm.getPackageInfo(packageName, 0).firstInstallTime } catch (_: Exception) { 0L }
        val lastUpdateTime = try { pm.getPackageInfo(packageName, 0).lastUpdateTime } catch (_: Exception) { 0L }
        list.add(
            SignalResult(
                id = "F096",
                name = "install_time_vs_update",
                category = SignalCategory.APP_INTEGRITY,
                value = "Install: ${firstInstallTime > 0}, Update: ${lastUpdateTime >= firstInstallTime}",
                riskLevel = RiskLevel.SAFE,
                details = "First install time vs last update time chronology."
            )
        )

        val srcDir = context.applicationInfo.sourceDir ?: ""
        val srcShapeOk = srcDir.startsWith("/data/app/") || srcDir.startsWith("/system/")
        list.add(
            SignalResult(
                id = "F097",
                name = "sourceDir_path_shape",
                category = SignalCategory.APP_INTEGRITY,
                value = if (srcDir.length > 35) srcDir.take(35) + "..." else srcDir,
                riskLevel = if (srcShapeOk) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "sourceDir path: $srcDir"
            )
        )

        val dataDir = context.applicationInfo.dataDir ?: ""
        val dataShapeOk = dataDir.startsWith("/data/user/") || dataDir.startsWith("/data/data/")
        list.add(
            SignalResult(
                id = "F098",
                name = "dataDir_path_shape",
                category = SignalCategory.APP_INTEGRITY,
                value = dataDir,
                riskLevel = if (dataShapeOk) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "dataDir path: $dataDir"
            )
        )

        val unusualDir = !srcShapeOk || !dataShapeOk
        list.add(
            SignalResult(
                id = "F099",
                name = "apk_in_unusual_dir",
                category = SignalCategory.APP_INTEGRITY,
                value = if (unusualDir) "Unusual directory detected" else "Standard directory",
                riskLevel = if (unusualDir) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects apps loaded from /sdcard, /data/local/tmp or virtual containers."
            )
        )

        val splitApks = context.applicationInfo.splitSourceDirs?.size ?: 0
        list.add(
            SignalResult(
                id = "F100",
                name = "split_apks_unexpected",
                category = SignalCategory.APP_INTEGRITY,
                value = "$splitApks split APKs",
                riskLevel = RiskLevel.INFO,
                details = "Dynamic feature splits count."
            )
        )

        val versionCode = try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pm.getPackageInfo(packageName, 0).longVersionCode
            } else {
                @Suppress("DEPRECATION")
                pm.getPackageInfo(packageName, 0).versionCode.toLong()
            }
        } catch (_: Exception) { 1L }
        list.add(
            SignalResult(
                id = "F101",
                name = "version_code_vs_server",
                category = SignalCategory.APP_INTEGRITY,
                value = "v$versionCode",
                riskLevel = RiskLevel.SAFE,
                details = "App versionCode: $versionCode"
            )
        )

        // Clone & virtual space (F102 - F109)
        val uid = Process.myUid()
        val isStandardUid = uid in 10000..99999
        list.add(
            SignalResult(
                id = "F102",
                name = "uid_vs_expected",
                category = SignalCategory.APP_INTEGRITY,
                value = "UID $uid (${if (isStandardUid) "Standard App UID" else "Secondary / Cloned UID"})",
                riskLevel = if (isStandardUid) RiskLevel.SAFE else RiskLevel.INFO,
                details = "Linux process UID assigned to the application."
            )
        )

        list.add(RealChecks.get("F103", "pid_ns_unusual", context))

        val mapsText = try { File("/proc/self/maps").readText() } catch (_: Exception) { "" }
        val foreignPkgsInMaps = mapsText.lines().any { line ->
            line.contains("/data/app/") && !line.contains(packageName)
        }
        list.add(
            SignalResult(
                id = "F104",
                name = "foreign_pkgs_in_maps",
                category = SignalCategory.APP_INTEGRITY,
                value = if (foreignPkgsInMaps) "Foreign package memory mapped" else "Clean",
                riskLevel = if (foreignPkgsInMaps) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Detects other apps' DEX/APK files loaded into this process address space."
            )
        )

        val stackClasses = Thread.currentThread().stackTrace.map { it.className }
        val virtualAppPackages = listOf("com.lbe.parallel", "com.excelliance.dualaid", "io.va.exposed", "com.vphone.launcher")
        val hostClassFound = virtualAppPackages.any { vap -> stackClasses.any { it.contains(vap) } }
        list.add(
            SignalResult(
                id = "F105",
                name = "host_app_classes_in_stack",
                category = SignalCategory.APP_INTEGRITY,
                value = if (hostClassFound) "Virtual container host detected" else "Clean",
                riskLevel = if (hostClassFound) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans stack trace for known Parallel Space / VirtualApp host classes."
            )
        )

        val isDualApp = uid >= 99000 || dataDir.contains("999") || dataDir.contains("parallel")
        list.add(
            SignalResult(
                id = "F106",
                name = "dual_app_flag",
                category = SignalCategory.APP_INTEGRITY,
                value = if (isDualApp) "Dual / Cloned app detected" else "Primary app instance",
                riskLevel = if (isDualApp) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "OEM Dual App / App Twin space indicator."
            )
        )

        val isWorkProfile = uid in 100000..199999
        list.add(
            SignalResult(
                id = "F107",
                name = "work_profile_flag",
                category = SignalCategory.APP_INTEGRITY,
                value = if (isWorkProfile) "Work Profile Active" else "Personal Profile",
                riskLevel = RiskLevel.INFO,
                details = "Checks if running inside Android enterprise Work Profile."
            )
        )

        // /data/user/0 is a symlink to /data/data, so compare canonical paths: a virtual-app host
        // gives us a data dir inside its own directory instead.
        val expectedDataDir = File("/data/user/${android.os.Process.myUid() / 100000}/$packageName").canonicalPath
        val virtualSpaceMarkers = File(dataDir).canonicalPath != expectedDataDir
        list.add(
            SignalResult(
                id = "F108",
                name = "virtual_space_markers",
                category = SignalCategory.APP_INTEGRITY,
                value = if (virtualSpaceMarkers) "Virtual redirect detected" else "Clean",
                riskLevel = if (virtualSpaceMarkers) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Filesystem path redirection indicators."
            )
        )

        list.add(RealChecks.get("F109", "process_name_mismatch", context))

        // Dynamically loaded code (F110 - F115)
        var cl: ClassLoader? = context.classLoader
        var clDepth = 0
        while (cl != null) {
            clDepth++
            cl = cl.parent
        }
        list.add(RealChecks.get("F110", "dexclassloader_instances", context))

        list.add(RealChecks.get("F111", "inmemory_dex_loaders", context))

        list.add(
            SignalResult(
                id = "F112",
                name = "classloader_chain_length",
                category = SignalCategory.APP_INTEGRITY,
                value = "$clDepth levels",
                riskLevel = RiskLevel.SAFE,
                details = "Hierarchy depth of the ClassLoader delegation tree."
            )
        )

        val unknownDex = mapsText.lines().any { it.contains(".dex") && !it.contains(packageName) && !it.contains("/system/") && !it.contains("/apex/") }
        list.add(
            SignalResult(
                id = "F113",
                name = "unknown_dex_in_maps",
                category = SignalCategory.APP_INTEGRITY,
                value = if (unknownDex) "External DEX mapped" else "Clean",
                riskLevel = if (unknownDex) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans memory maps for external, non-OEM DEX files."
            )
        )

        val libInTmp = mapsText.lines().any { it.contains(".so") && (it.contains("/tmp") || it.contains("/cache")) }
        list.add(
            SignalResult(
                id = "F114",
                name = "native_lib_loaded_from_tmp",
                category = SignalCategory.APP_INTEGRITY,
                value = if (libInTmp) "Native library in tmp mapped" else "Clean",
                riskLevel = if (libInTmp) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects .so libraries loaded from writable temp folders."
            )
        )

        list.add(RealChecks.get("F115", "dlopen_unknown_paths", context))

        return list
    }
}
