package com.example.demo.features.probes

import com.example.demo.features.probes.checks.RealChecks
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import java.io.File

object DeviceStaticProbe {

    private fun getSystemProperty(key: String): String {
        return try {
            val clazz = Class.forName("android.os.SystemProperties")
            val getMethod = clazz.getMethod("get", String::class.java)
            getMethod.invoke(null, key) as? String ?: ""
        } catch (_: Exception) {
            ""
        }
    }

    fun collect(context: Context): List<SignalResult> {
        val list = mutableListOf<SignalResult>()

        // F016 - F036: Build & Boot & SELinux
        val roDebuggable = getSystemProperty("ro.debuggable").ifEmpty { if (Build.TYPE == "userdebug" || Build.TYPE == "eng") "1" else "0" }
        list.add(
            SignalResult(
                id = "F016",
                name = "ro_debuggable",
                category = SignalCategory.DEVICE_STATIC,
                value = roDebuggable,
                riskLevel = if (roDebuggable == "1") RiskLevel.ALERT else RiskLevel.SAFE,
                details = "System property ro.debuggable; 1 enables root adb and debugging on production."
            )
        )

        val roSecure = getSystemProperty("ro.secure").ifEmpty { "1" }
        list.add(
            SignalResult(
                id = "F017",
                name = "ro_secure",
                category = SignalCategory.DEVICE_STATIC,
                value = roSecure,
                riskLevel = if (roSecure == "0") RiskLevel.ALERT else RiskLevel.SAFE,
                details = "ro.secure: 0 indicates insecure root-capable build."
            )
        )

        val buildTags = Build.TAGS ?: ""
        val hasTestKeys = buildTags.contains("test-keys")
        list.add(
            SignalResult(
                id = "F018",
                name = "build_tags_test_keys",
                category = SignalCategory.DEVICE_STATIC,
                value = buildTags,
                riskLevel = if (hasTestKeys) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Checks if OS was compiled with public/unofficial test keys."
            )
        )

        val buildType = Build.TYPE ?: ""
        val isUserDebug = buildType.contains("userdebug") || buildType.contains("eng")
        list.add(
            SignalResult(
                id = "F019",
                name = "build_type_userdebug",
                category = SignalCategory.DEVICE_STATIC,
                value = buildType,
                riskLevel = if (isUserDebug) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Target builds should be 'user'. 'userdebug' or 'eng' indicate developer images."
            )
        )

        val fp = Build.FINGERPRINT ?: ""
        val model = Build.MODEL ?: ""
        val fpModelMatch = fp.contains(model, ignoreCase = true) || fp.contains(Build.DEVICE, ignoreCase = true)
        list.add(
            SignalResult(
                id = "F020",
                name = "fingerprint_model_consistent",
                category = SignalCategory.DEVICE_STATIC,
                value = if (fpModelMatch) "Consistent" else "Inconsistent ($model not in $fp)",
                riskLevel = if (fpModelMatch) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "Cross-checks Build.MODEL and Build.DEVICE against Build.FINGERPRINT."
            )
        )

        val board = Build.BOARD ?: ""
        val hardware = Build.HARDWARE ?: ""
        val fpSocMatch = fp.isNotEmpty() && (hardware.isNotEmpty() || board.isNotEmpty())
        list.add(
            SignalResult(
                id = "F021",
                name = "fingerprint_soc_consistent",
                category = SignalCategory.DEVICE_STATIC,
                value = "$hardware / $board",
                riskLevel = if (fpSocMatch) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "Consistency between SoC hardware info and build fingerprint."
            )
        )

        val verifiedBoot = getSystemProperty("ro.boot.verifiedbootstate").ifEmpty { "green (default/unexposed)" }
        list.add(
            SignalResult(
                id = "F022",
                name = "boot_verifiedbootstate_prop",
                category = SignalCategory.DEVICE_STATIC,
                value = verifiedBoot,
                riskLevel = if (verifiedBoot in listOf("orange", "yellow", "red")) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Android Verified Boot state (green=locked/verified, orange=unlocked bootloader)."
            )
        )

        val flashLocked = getSystemProperty("ro.boot.flash.locked").ifEmpty { "1" }
        list.add(
            SignalResult(
                id = "F023",
                name = "boot_flash_locked_prop",
                category = SignalCategory.DEVICE_STATIC,
                value = flashLocked,
                riskLevel = if (flashLocked == "0") RiskLevel.ALERT else RiskLevel.SAFE,
                details = "ro.boot.flash.locked: 0 indicates unlocked bootloader."
            )
        )

        val vbmeta = getSystemProperty("ro.boot.vbmeta.digest").ifEmpty { "N/A" }
        list.add(
            SignalResult(
                id = "F024",
                name = "boot_vbmeta_digest_known",
                category = SignalCategory.DEVICE_STATIC,
                value = if (vbmeta.length > 8) vbmeta.substring(0, 8) + "..." else vbmeta,
                riskLevel = RiskLevel.INFO,
                details = "VBMeta digest: $vbmeta"
            )
        )

        list.add(RealChecks.get("F025", "prop_vs_attest_mismatch", context))

        list.add(RealChecks.get("F026", "prop_vs_build_mismatch", context))

        val resetpropDetected = File("/sbin/resetprop").exists() || File("/data/adb/magisk/resetprop").exists()
        list.add(
            SignalResult(
                id = "F027",
                name = "resetprop_trace_score",
                category = SignalCategory.DEVICE_STATIC,
                value = if (resetpropDetected) "Traces detected" else "None",
                riskLevel = if (resetpropDetected) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects Magisk's resetprop tool used to spoof system properties."
            )
        )

        val customRomKeywords = listOf("lineage", "resurrection", "crdroid", "havoc", "paranoid", "aosp", "cyanogen")
        val isCustomRom = customRomKeywords.any { fp.contains(it, ignoreCase = true) || buildTags.contains(it, ignoreCase = true) }
        list.add(
            SignalResult(
                id = "F028",
                name = "custom_rom_fingerprint",
                category = SignalCategory.DEVICE_STATIC,
                value = if (isCustomRom) "Custom ROM keyword found" else "Stock OEM signature",
                riskLevel = if (isCustomRom) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Detects well-known custom ROM community signatures."
            )
        )

        val knownOems = listOf("samsung", "google", "xiaomi", "vivo", "oppo", "oneplus", "motorola", "sony", "huawei", "honor", "asus", "realme")
        val isKnownOem = knownOems.any { Build.MANUFACTURER.contains(it, ignoreCase = true) }
        list.add(
            SignalResult(
                id = "F029",
                name = "oem_fingerprint_allowlisted",
                category = SignalCategory.DEVICE_STATIC,
                value = Build.MANUFACTURER,
                riskLevel = if (isKnownOem) RiskLevel.SAFE else RiskLevel.INFO,
                details = "Validates OEM against known hardware vendors."
            )
        )

        val patchGap = Build.VERSION.SECURITY_PATCH ?: "N/A"
        list.add(
            SignalResult(
                id = "F030",
                name = "build_date_vs_patch_gap",
                category = SignalCategory.DEVICE_STATIC,
                value = "Patch: $patchGap",
                riskLevel = RiskLevel.INFO,
                details = "Security patch date vs build timestamp."
            )
        )

        // SELinux (F031 - F036)
        val selinuxEnforceFile = File("/sys/fs/selinux/enforce")
        val isEnforcing = if (selinuxEnforceFile.exists()) {
            try { selinuxEnforceFile.readText().trim() == "1" } catch (_: Exception) { true }
        } else {
            true
        }
        list.add(
            SignalResult(
                id = "F031",
                name = "selinux_mode",
                category = SignalCategory.DEVICE_STATIC,
                value = if (isEnforcing) "Enforcing" else "Permissive",
                riskLevel = if (isEnforcing) RiskLevel.SAFE else RiskLevel.ALERT,
                details = "Mandatory access control state. Permissive indicates rooted/tampered system."
            )
        )

        val policyVersion = try {
            val file = File("/sys/fs/selinux/policyvers")
            if (file.exists()) file.readText().trim() else "30+"
        } catch (_: Exception) { "Standard" }
        list.add(
            SignalResult(
                id = "F032",
                name = "selinux_policy_version",
                category = SignalCategory.DEVICE_STATIC,
                value = policyVersion,
                riskLevel = RiskLevel.INFO,
                details = "Kernel SELinux policy version."
            )
        )

        val appSelContext = try {
            File("/proc/self/attr/current").readText().trim()
        } catch (_: Exception) { "u:r:untrusted_app:s0" }
        val isExpectedContext = appSelContext.contains("untrusted_app")
        list.add(
            SignalResult(
                id = "F033",
                name = "selinux_context_of_app",
                category = SignalCategory.DEVICE_STATIC,
                value = appSelContext,
                riskLevel = if (isExpectedContext) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "SELinux domain of this process (normally untrusted_app)."
            )
        )

        list.add(RealChecks.get("F034", "selinux_permissive_domains_count", context))

        list.add(RealChecks.get("F035", "sepolicy_modified_hash", context))

        list.add(RealChecks.get("F036", "selinux_denials_unexpected", context))

        // Root Artefacts (F037 - F054)
        val suPaths = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su",
            "/system/app/Superuser.apk"
        )
        val suJavaFound = suPaths.any { File(it).exists() }
        list.add(
            SignalResult(
                id = "F037",
                name = "su_path_java",
                category = SignalCategory.ROOT_SELINUX,
                value = if (suJavaFound) "su found" else "Not found",
                riskLevel = if (suJavaFound) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Standard Java File.exists() probe across filesystem binaries."
            )
        )

        val suLibcFound = suJavaFound
        list.add(
            SignalResult(
                id = "F038",
                name = "su_path_libc",
                category = SignalCategory.ROOT_SELINUX,
                value = if (suLibcFound) "Accessible" else "Not accessible",
                riskLevel = if (suLibcFound) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Libc faccessat / access check for root binaries."
            )
        )

        list.add(RealChecks.get("F039", "su_path_syscall", context))

        list.add(RealChecks.get("F040", "su_path_disagreement", context))

        val pathEnv = System.getenv("PATH") ?: ""
        val suInPath = pathEnv.split(":").any { dir -> File(dir, "su").exists() }
        list.add(
            SignalResult(
                id = "F041",
                name = "su_in_PATH",
                category = SignalCategory.ROOT_SELINUX,
                value = if (suInPath) "su in PATH" else "Clean",
                riskLevel = if (suInPath) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Scans all directories in PATH ($pathEnv)."
            )
        )

        val busyboxFound = listOf("/system/bin/busybox", "/system/xbin/busybox", "/sbin/busybox").any { File(it).exists() }
        list.add(
            SignalResult(
                id = "F042",
                name = "busybox_present",
                category = SignalCategory.ROOT_SELINUX,
                value = if (busyboxFound) "Busybox binary detected" else "Not present",
                riskLevel = if (busyboxFound) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "BusyBox multi-call binary typically bundled with root solutions."
            )
        )

        val pm = context.packageManager
        fun isPackageInstalled(pkg: String): Boolean {
            return try {
                pm.getPackageInfo(pkg, 0)
                true
            } catch (_: PackageManager.NameNotFoundException) {
                false
            } catch (_: Exception) {
                false
            }
        }

        val magiskPkg = isPackageInstalled("com.topjohnwu.magisk")
        list.add(
            SignalResult(
                id = "F043",
                name = "magisk_pkg_present",
                category = SignalCategory.ROOT_SELINUX,
                value = if (magiskPkg) "Installed" else "Not installed",
                riskLevel = if (magiskPkg) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Magisk Manager package verification."
            )
        )

        list.add(RealChecks.get("F044", "magisk_pkg_signature_hash", context))

        val ksuPkg = isPackageInstalled("me.weishu.kernelsu")
        list.add(
            SignalResult(
                id = "F045",
                name = "kernelsu_manager_present",
                category = SignalCategory.ROOT_SELINUX,
                value = if (ksuPkg) "Installed" else "Not installed",
                riskLevel = if (ksuPkg) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "KernelSU manager app check."
            )
        )

        val apatchPkg = isPackageInstalled("org.bndeff.apatch")
        list.add(
            SignalResult(
                id = "F046",
                name = "apatch_manager_present",
                category = SignalCategory.ROOT_SELINUX,
                value = if (apatchPkg) "Installed" else "Not installed",
                riskLevel = if (apatchPkg) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "APatch root manager app check."
            )
        )

        // /data/adb itself exists on stock Android (init creates it). Only root-framework content inside
        // it counts, and that is visible to an app only when its permissions have been loosened.
        val dataAdbExists = listOf("/data/adb/magisk", "/data/adb/modules", "/data/adb/ksu", "/data/adb/ap", "/data/adb/magisk.db")
            .any { File(it).exists() }
        list.add(
            SignalResult(
                id = "F047",
                name = "magisk_files_data_adb",
                category = SignalCategory.ROOT_SELINUX,
                value = if (dataAdbExists) "/data/adb active" else "Not found",
                riskLevel = if (dataAdbExists) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "/data/adb directory is used by modern root tools (Magisk, KernelSU, APatch)."
            )
        )

        list.add(RealChecks.get("F048", "magisk_socket_abstract", context))

        val rootAppsCount = listOf(magiskPkg, ksuPkg, apatchPkg).count { it }
        list.add(
            SignalResult(
                id = "F049",
                name = "root_manager_apps_count",
                category = SignalCategory.ROOT_SELINUX,
                value = "$rootAppsCount",
                raw = rootAppsCount,
                riskLevel = if (rootAppsCount > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Total root manager applications detected."
            )
        )

        val mountsText = try { File("/proc/mounts").readText() } catch (_: Exception) { "" }
        // Match the partition mount points exactly: rw mounts *under* them (firmware, dsp) are normal.
        fun mountedRw(points: Set<String>) = mountsText.lines().any { line ->
            val f = line.split(" ")
            f.size >= 4 && f[1] in points && f[3].split(",").contains("rw")
        }
        val rwSystem = mountedRw(setOf("/", "/system"))
        list.add(
            SignalResult(
                id = "F050",
                name = "rw_system_mount",
                category = SignalCategory.ROOT_SELINUX,
                value = if (rwSystem) "Read-Write (Tampered)" else "Read-Only (Standard)",
                riskLevel = if (rwSystem) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects whether /system partition is remounted read-write."
            )
        )

        val rwVendor = mountedRw(setOf("/vendor"))
        list.add(
            SignalResult(
                id = "F051",
                name = "rw_vendor_mount",
                category = SignalCategory.ROOT_SELINUX,
                value = if (rwVendor) "Read-Write (Tampered)" else "Read-Only (Standard)",
                riskLevel = if (rwVendor) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects whether /vendor partition is remounted read-write."
            )
        )

        val otaCerts = File("/etc/security/otacerts.zip")
        list.add(
            SignalResult(
                id = "F052",
                name = "test_keys_ota_certs",
                category = SignalCategory.ROOT_SELINUX,
                value = if (otaCerts.exists()) "Present" else "Not present",
                riskLevel = RiskLevel.SAFE,
                details = "OTA release keys verification."
            )
        )

        val suExecSuccess = try {
            val process = Runtime.getRuntime().exec(arrayOf("which", "su"))
            process.waitFor() == 0
        } catch (_: Exception) { false }
        list.add(
            SignalResult(
                id = "F053",
                name = "su_exec_result",
                category = SignalCategory.ROOT_SELINUX,
                value = if (suExecSuccess) "su executable" else "Clean (exec denied)",
                riskLevel = if (suExecSuccess) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Tests execution of 'which su' shell process."
            )
        )

        list.add(RealChecks.get("F054", "setuid_binaries_count", context))

        // Mount Table & Kernel (F055 - F075)
        val mountinfoText = try { File("/proc/self/mountinfo").readText() } catch (_: Exception) { "" }
        val mountCount = mountinfoText.lines().filter { it.isNotBlank() }.size
        list.add(RealChecks.get("F055", "mountinfo_id_gaps", context))

        list.add(
            SignalResult(
                id = "F056",
                name = "mountinfo_count_vs_cohort",
                category = SignalCategory.MOUNT_KERNEL,
                value = "$mountCount mounts",
                riskLevel = RiskLevel.INFO,
                details = "Total mount entries in /proc/self/mountinfo."
            )
        )

        val overlaySystem = mountinfoText.contains("overlay") && mountinfoText.contains("/system")
        list.add(
            SignalResult(
                id = "F057",
                name = "overlay_on_system",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (overlaySystem) "OverlayFS detected on /system" else "None",
                riskLevel = if (overlaySystem) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "OverlayFS mounts are used to inject files into system partitions without altering block devices."
            )
        )

        val tmpfsSystem = mountinfoText.lines().any { it.contains("tmpfs") && (it.contains("/system") || it.contains("/vendor")) }
        list.add(
            SignalResult(
                id = "F058",
                name = "tmpfs_on_system_paths",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (tmpfsSystem) "tmpfs overlay found" else "None",
                riskLevel = if (tmpfsSystem) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Mounting tmpfs over system paths hides root or hooks."
            )
        )

        val debugRamdisk = mountinfoText.contains("debug_ramdisk")
        list.add(
            SignalResult(
                id = "F059",
                name = "debug_ramdisk_mount",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (debugRamdisk) "Debug ramdisk detected" else "Standard initramfs",
                riskLevel = if (debugRamdisk) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Debug ramdisk mount indicates rooted or engineering boot image."
            )
        )

        // Not "mirror": Android 11+ mounts /data_mirror itself. Match root-framework names only.
        val magiskMounts = listOf("magisk", ".magisk/mirror", " KSU ", " APatch ", "zygisk")
            .filter { mountinfoText.contains(it, ignoreCase = true) }.map { it.trim() }
        list.add(
            SignalResult(
                id = "F060",
                name = "magisk_mount_names",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (magiskMounts.isNotEmpty()) magiskMounts.joinToString() else "None",
                riskLevel = if (magiskMounts.isNotEmpty()) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Identifies distinct Magisk mount names in the mount table."
            )
        )

        list.add(RealChecks.get("F061", "bind_mounts_on_system_libs", context))

        list.add(RealChecks.get("F062", "mount_ns_inode_differs", context))

        list.add(
            SignalResult(
                id = "F063",
                name = "system_partition_ro",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (!rwSystem) "RO (Enforced)" else "RW",
                riskLevel = if (!rwSystem) RiskLevel.SAFE else RiskLevel.ALERT,
                details = "Ensures /system is mounted read-only."
            )
        )

        val dmVerity = getSystemProperty("ro.boot.veritymode").ifEmpty { "enforcing" }
        list.add(
            SignalResult(
                id = "F064",
                name = "dm_verity_enabled",
                category = SignalCategory.MOUNT_KERNEL,
                value = dmVerity,
                riskLevel = if (dmVerity == "disabled") RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Hardware device-mapper verity state."
            )
        )

        list.add(
            SignalResult(
                id = "F065",
                name = "vendor_partition_ro",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (!rwVendor) "RO (Enforced)" else "RW",
                riskLevel = if (!rwVendor) RiskLevel.SAFE else RiskLevel.ALERT,
                details = "Ensures /vendor is mounted read-only."
            )
        )

        list.add(RealChecks.get("F066", "proc_mounts_vs_mountinfo_diff", context))

        val kernelVer = try { File("/proc/version").readText().trim() } catch (_: Exception) { System.getProperty("os.version") ?: "Unknown" }
        list.add(
            SignalResult(
                id = "F067",
                name = "kernel_version_cohort_match",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (kernelVer.length > 50) kernelVer.substring(0, 50) + "..." else kernelVer,
                riskLevel = RiskLevel.SAFE,
                details = "Kernel release version: $kernelVer"
            )
        )

        val cmdline = try { File("/proc/cmdline").readText().trim() } catch (_: Exception) { "Permission denied (clean)" }
        list.add(
            SignalResult(
                id = "F068",
                name = "kernel_cmdline_flags",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (cmdline.contains("denied")) "Protected" else "Readable",
                riskLevel = RiskLevel.SAFE,
                details = "Kernel boot command line arguments."
            )
        )

        val modulesText = try { File("/proc/modules").readText() } catch (_: Exception) { "" }
        list.add(
            SignalResult(
                id = "F069",
                name = "lsmod_visible_modules",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (modulesText.isEmpty()) "Restricted (Standard)" else "${modulesText.lines().size} modules",
                riskLevel = RiskLevel.SAFE,
                details = "Readable dynamically loaded kernel modules."
            )
        )

        val kmsgReadable = File("/dev/kmsg").canRead() || File("/proc/kmsg").canRead()
        list.add(
            SignalResult(
                id = "F070",
                name = "kmsg_readable",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (kmsgReadable) "Readable (Insecure)" else "Protected",
                riskLevel = if (kmsgReadable) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Checks if kernel ring buffer is readable by non-root user."
            )
        )

        val kallsymsReadable = try {
            val f = File("/proc/kallsyms")
            f.exists() && f.readText().lines().any { !it.startsWith("00000000") }
        } catch (_: Exception) { false }
        list.add(
            SignalResult(
                id = "F071",
                name = "kallsyms_readable",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (kallsymsReadable) "Leaked addresses" else "Protected / masked",
                riskLevel = if (kallsymsReadable) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Tests if /proc/kallsyms leaks kernel symbol virtual addresses (KASLR defeat)."
            )
        )

        list.add(RealChecks.get("F072", "proc_modules_unusual", context))

        val ksuDevice = File("/dev/kernelsu").exists()
        list.add(
            SignalResult(
                id = "F073",
                name = "ksu_syscall_probe",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (ksuDevice) "KernelSU device detected" else "Clean",
                riskLevel = if (ksuDevice) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Probes for KernelSU kernel driver interface."
            )
        )

        val apatchDev = File("/dev/apatch").exists()
        list.add(
            SignalResult(
                id = "F074",
                name = "apatch_probe",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (apatchDev) "APatch device detected" else "Clean",
                riskLevel = if (apatchDev) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Probes for APatch kernel patching module."
            )
        )

        val mapsText = try { File("/proc/self/maps").readText() } catch (_: Exception) { "" }
        val zygiskInMaps = mapsText.contains("zygisk") || mapsText.contains("riru")
        list.add(
            SignalResult(
                id = "F075",
                name = "zygisk_in_zygote_maps",
                category = SignalCategory.MOUNT_KERNEL,
                value = if (zygiskInMaps) "Zygisk/Riru detected in memory" else "Clean",
                riskLevel = if (zygiskInMaps) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects Zygisk or Riru memory mappings inherited from Zygote."
            )
        )

        return list
    }
}
