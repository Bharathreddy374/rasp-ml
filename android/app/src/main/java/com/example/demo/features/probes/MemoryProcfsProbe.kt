package com.example.demo.features.probes

import com.example.demo.features.probes.checks.RealChecks
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import java.io.File

object MemoryProcfsProbe {

    fun collect(): List<SignalResult> {
        val list = mutableListOf<SignalResult>()

        val mapsLines = try { File("/proc/self/maps").readLines() } catch (_: Exception) { emptyList() }
        val regionCount = mapsLines.size
        val fileBacked = mapsLines.count { it.contains("/") }
        val fileBackedRatio = if (regionCount > 0) "%.2f".format(fileBacked.toFloat() / regionCount) else "1.00"
        val rwxRegions = mapsLines.count { it.contains("rwxp") }
        val deletedMappings = mapsLines.count { it.contains("(deleted)") }
        val backingFiles = mapsLines.mapNotNull {
            val parts = it.split("\\s+".toRegex())
            if (parts.size >= 6 && parts[5].startsWith("/")) parts[5] else null
        }.distinct().size

        list.add(
            SignalResult(
                id = "F176",
                name = "maps_region_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$regionCount regions",
                riskLevel = RiskLevel.INFO,
                details = "Total memory-mapped virtual address regions in /proc/self/maps."
            )
        )

        list.add(
            SignalResult(
                id = "F177",
                name = "maps_file_backed_ratio",
                category = SignalCategory.MEMORY_PROCFS,
                value = fileBackedRatio,
                riskLevel = RiskLevel.INFO,
                details = "Ratio of file-backed memory regions vs total mappings."
            )
        )

        val anonExecBytes = mapsLines.filter { it.contains("r-xp") && !it.contains("/") }.sumOf { line ->
            val range = line.substringBefore(" ").split("-")
            if (range.size == 2) {
                val start = range[0].toLongOrNull(16) ?: 0L
                val end = range[1].toLongOrNull(16) ?: 0L
                end - start
            } else 0L
        } / 1024
        list.add(
            SignalResult(
                id = "F178",
                name = "anon_exec_bytes",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$anonExecBytes KB",
                riskLevel = if (anonExecBytes > 2048) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Anonymous executable memory allocated by JIT, loaders or trampolines."
            )
        )

        list.add(
            SignalResult(
                id = "F179",
                name = "anon_rwx_regions",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$rwxRegions RWX regions",
                riskLevel = if (rwxRegions > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Read-Write-Execute pages violate W^X memory security policy."
            )
        )

        list.add(
            SignalResult(
                id = "F180",
                name = "deleted_mappings_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$deletedMappings deleted mappings",
                riskLevel = if (deletedMappings > 10) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Files deleted from disk after being mapped into memory (stealth injection)."
            )
        )

        list.add(
            SignalResult(
                id = "F181",
                name = "distinct_backing_files",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$backingFiles distinct files",
                riskLevel = RiskLevel.INFO,
                details = "Count of unique files mapped into process memory space."
            )
        )

        list.add(RealChecks.get("F182", "region_size_entropy", null))

        list.add(RealChecks.get("F183", "jaccard_vs_cohort_files", null))

        // Partitions that legitimately hold platform and vendor libraries, plus this app's own install dir.
        val trustedLibDirs = listOf("/system/", "/system_ext/", "/product/", "/vendor/", "/odm/", "/apex/", "/data/app/")
        val unknownSo = mapsLines.mapNotNull {
            val parts = it.trim().split("\\s+".toRegex(), limit = 6)
            parts.getOrNull(5)?.takeIf { p -> p.startsWith("/") && p.contains(".so") }
        }.distinct().count { path -> trustedLibDirs.none { path.startsWith(it) } }
        list.add(
            SignalResult(
                id = "F184",
                name = "unknown_so_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$unknownSo external .so files",
                riskLevel = if (unknownSo > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Native shared libraries loaded from unknown directory paths."
            )
        )

        val memfdCount = mapsLines.count { it.contains("memfd:") && !it.contains("jit-") }
        list.add(
            SignalResult(
                id = "F185",
                name = "memfd_mappings",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$memfdCount memfd regions",
                riskLevel = if (memfdCount > 0) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "In-memory file descriptors created with memfd_create."
            )
        )

        val ashmemExec = mapsLines.count { it.contains("/dev/ashmem") && it.contains("x") }
        list.add(
            SignalResult(
                id = "F186",
                name = "ashmem_exec_maps",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$ashmemExec regions",
                riskLevel = if (ashmemExec > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Executable Android shared memory segments."
            )
        )

        val hasVdso = mapsLines.any { it.contains("[vdso]") }
        list.add(
            SignalResult(
                id = "F187",
                name = "vdso_vvar_odd",
                category = SignalCategory.MEMORY_PROCFS,
                value = if (hasVdso) "Standard [vdso]" else "Missing [vdso]",
                riskLevel = if (hasVdso) RiskLevel.SAFE else RiskLevel.SUSPICIOUS,
                details = "Kernel Virtual Dynamic Shared Object memory layout."
            )
        )

        // Process status (F188 - F193)
        val statusMap = mutableMapOf<String, String>()
        try {
            File("/proc/self/status").forEachLine { line ->
                val parts = line.split(":")
                if (parts.size >= 2) {
                    statusMap[parts[0].trim()] = parts[1].trim()
                }
            }
        } catch (_: Exception) {}

        val seccomp = statusMap["Seccomp"] ?: "2"
        list.add(
            SignalResult(
                id = "F188",
                name = "seccomp_mode",
                category = SignalCategory.MEMORY_PROCFS,
                value = "Mode $seccomp (${if (seccomp == "2") "SECCOMP_MODE_FILTER active" else "Unrestricted"})",
                riskLevel = if (seccomp == "2") RiskLevel.SAFE else RiskLevel.ALERT,
                details = "Linux Seccomp syscall filter state."
            )
        )

        val capEff = statusMap["CapEff"] ?: "0000000000000000"
        list.add(
            SignalResult(
                id = "F189",
                name = "cap_effective",
                category = SignalCategory.MEMORY_PROCFS,
                value = capEff,
                riskLevel = if (capEff != "0000000000000000") RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Linux POSIX effective capabilities mask (should be 0 for standard apps)."
            )
        )

        val capBnd = statusMap["CapBnd"] ?: "Standard"
        list.add(
            SignalResult(
                id = "F190",
                name = "cap_bounding_diff",
                category = SignalCategory.MEMORY_PROCFS,
                value = capBnd,
                riskLevel = RiskLevel.SAFE,
                details = "Bounding capability set difference."
            )
        )

        // Stock app processes report 0: zygote installs the seccomp filter without no_new_privs.
        // Recorded for per-model comparison, not judged here.
        val noNewPrivs = statusMap["NoNewPrivs"]
        list.add(
            SignalResult(
                id = "F191",
                name = "nonewprivs",
                category = SignalCategory.MEMORY_PROCFS,
                value = when (noNewPrivs) { "1" -> "Set (1)"; "0" -> "Not set (0)"; else -> "Unreadable" },
                raw = noNewPrivs?.toIntOrNull(),
                riskLevel = RiskLevel.INFO,
                implemented = noNewPrivs != null,
                details = "PR_SET_NO_NEW_PRIVS flag of this process (0 is normal for Android apps)."
            )
        )

        val threadCount = statusMap["Threads"]?.toIntOrNull() ?: 15
        list.add(
            SignalResult(
                id = "F192",
                name = "threads_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$threadCount threads",
                riskLevel = RiskLevel.INFO,
                details = "Total active OS threads inside this application process."
            )
        )

        val vmRss = statusMap["VmRSS"] ?: "N/A"
        list.add(
            SignalResult(
                id = "F193",
                name = "vmrss_vs_cohort",
                category = SignalCategory.MEMORY_PROCFS,
                value = vmRss,
                riskLevel = RiskLevel.INFO,
                details = "Resident set size memory footprint."
            )
        )

        // Threads (F194 - F199)
        val taskDir = File("/proc/self/task")
        val threadNames = taskDir.listFiles()?.mapNotNull { task ->
            try { File(task, "comm").readText().trim() } catch (_: Exception) { null }
        } ?: emptyList()

        val unnamedCount = threadNames.count { it.isBlank() }
        // Specific tool thread names only: generic words like "patch" or "hook" match normal threads
        // (Kotlin's "DefaultDispatcher-worker" contains "patch").
        val suspiciousNames = listOf("gum-js", "frida", "linjector", "xposed", "lspd", "magisk", "zygisk", "gmain", "gdbus")
        val suspiciousThreads = threadNames.filter { name -> suspiciousNames.any { name.contains(it, ignoreCase = true) } }

        list.add(RealChecks.get("F194", "thread_name_entropy", null))

        list.add(
            SignalResult(
                id = "F195",
                name = "unnamed_threads_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$unnamedCount unnamed threads",
                riskLevel = if (unnamedCount > 3) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "Threads created without a name string via pthread_create directly."
            )
        )

        list.add(
            SignalResult(
                id = "F196",
                name = "suspicious_thread_names",
                category = SignalCategory.MEMORY_PROCFS,
                value = if (suspiciousThreads.isNotEmpty()) suspiciousThreads.joinToString() else "None",
                riskLevel = if (suspiciousThreads.isNotEmpty()) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Detects threads with signatures matching known injection engines."
            )
        )

        list.add(RealChecks.get("F197", "threads_vs_cohort", null))

        list.add(RealChecks.get("F198", "thread_start_addrs_anon", null))

        list.add(RealChecks.get("F199", "thread_priority_odd", null))

        // File descriptors (F200 - F205)
        val fds = try { File("/proc/self/fd").listFiles() } catch (_: Exception) { null }
        val fdCount = fds?.size ?: 0

        var socketCount = 0
        var pipeCount = 0
        var ashmemCount = 0
        var tmpCount = 0
        var procMemCount = 0

        fds?.forEach { fd ->
            try {
                val target = fd.canonicalPath
                if (target.contains("socket")) socketCount++
                if (target.contains("pipe")) pipeCount++
                if (target.contains("ashmem")) ashmemCount++
                if (target.contains("/tmp") || target.contains("/data/local/tmp")) tmpCount++
                if (target.contains("/proc/") && target.contains("/mem")) procMemCount++
            } catch (_: Exception) {}
        }

        list.add(
            SignalResult(
                id = "F200",
                name = "fd_count",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$fdCount open descriptors",
                riskLevel = RiskLevel.INFO,
                details = "Total open file descriptors in /proc/self/fd."
            )
        )

        list.add(
            SignalResult(
                id = "F201",
                name = "fd_sockets_unusual",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$socketCount open sockets",
                riskLevel = RiskLevel.INFO,
                details = "Open UNIX/TCP/UDP domain sockets."
            )
        )

        list.add(
            SignalResult(
                id = "F202",
                name = "fd_pipes_unusual",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$pipeCount open pipes",
                riskLevel = if (pipeCount > 30) RiskLevel.SUSPICIOUS else RiskLevel.SAFE,
                details = "IPC pipes created for inter-process communication."
            )
        )

        list.add(
            SignalResult(
                id = "F203",
                name = "fd_ashmem",
                category = SignalCategory.MEMORY_PROCFS,
                value = "$ashmemCount ashmem descriptors",
                riskLevel = RiskLevel.INFO,
                details = "Android shared memory file descriptors."
            )
        )

        list.add(
            SignalResult(
                id = "F204",
                name = "fd_to_tmp_files",
                category = SignalCategory.MEMORY_PROCFS,
                value = if (tmpCount > 0) "$tmpCount files open in tmp" else "0 (Clean)",
                riskLevel = if (tmpCount > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Open handles to files in /data/local/tmp or /tmp."
            )
        )

        list.add(
            SignalResult(
                id = "F205",
                name = "fd_to_proc_mem",
                category = SignalCategory.MEMORY_PROCFS,
                value = if (procMemCount > 0) "Open handle to /proc/self/mem!" else "0 (Protected)",
                riskLevel = if (procMemCount > 0) RiskLevel.ALERT else RiskLevel.SAFE,
                details = "Open descriptor pointing to /proc/self/mem (direct memory tampering)."
            )
        )

        return list
    }
}
