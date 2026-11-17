package com.example.demo.features.probes.support

import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.ln

/**
 * Readers for /proc and friends. Every read that fails (SELinux denial, missing file) is
 * counted, so probe health (F353) can report how much of the device was not observable.
 */
object Proc {
    private val blocked = AtomicInteger(0)

    fun resetCounters() = blocked.set(0)
    fun blockedReads(): Int = blocked.get()

    fun read(path: String): String? = try {
        File(path).readText()
    } catch (_: Exception) {
        blocked.incrementAndGet()
        null
    }

    fun lines(path: String): List<String>? = read(path)?.lines()?.filter { it.isNotBlank() }

    data class Mapping(val start: Long, val end: Long, val perms: String, val path: String) {
        val size: Long get() = end - start
    }

    /** /proc/self/maps, parsed. Null when unreadable. */
    fun maps(): List<Mapping>? = lines("/proc/self/maps")?.mapNotNull { line ->
        val f = line.trim().split(Regex("\\s+"), limit = 6)
        if (f.size < 5) return@mapNotNull null
        val range = f[0].split("-")
        val start = range.getOrNull(0)?.toLongOrNull(16) ?: return@mapNotNull null
        val end = range.getOrNull(1)?.toLongOrNull(16) ?: return@mapNotNull null
        Mapping(start, end, f[1], f.getOrElse(5) { "" }.trim())
    }

    data class MountInfo(
        val id: Int, val parent: Int, val root: String, val mountPoint: String,
        val options: String, val fsType: String, val source: String,
    )

    /** /proc/self/mountinfo, parsed. Null when unreadable. */
    fun mountInfo(): List<MountInfo>? = lines("/proc/self/mountinfo")?.mapNotNull { line ->
        val parts = line.split(" - ", limit = 2)
        if (parts.size != 2) return@mapNotNull null
        val a = parts[0].split(" ")
        val b = parts[1].split(" ")
        if (a.size < 6 || b.size < 2) return@mapNotNull null
        MountInfo(
            id = a[0].toIntOrNull() ?: return@mapNotNull null,
            parent = a[1].toIntOrNull() ?: -1,
            root = a[3], mountPoint = a[4], options = a[5],
            fsType = b[0], source = b[1],
        )
    }

    data class TaskStat(val tid: String, val name: String, val priority: Int, val nice: Int, val policy: Int)

    /** Every thread of this process, from /proc/self/task/<tid>/stat. */
    fun tasks(): List<TaskStat> {
        val dirs = File("/proc/self/task").listFiles() ?: run { blocked.incrementAndGet(); return emptyList() }
        return dirs.mapNotNull { dir ->
            val stat = read("${dir.path}/stat") ?: return@mapNotNull null
            val open = stat.indexOf('(')
            val close = stat.lastIndexOf(')')
            if (open < 0 || close < open) return@mapNotNull null
            val rest = stat.substring(close + 2).split(" ")
            // rest[0] is field 3 (state); field n is rest[n - 3]
            TaskStat(
                tid = dir.name,
                name = stat.substring(open + 1, close),
                priority = rest.getOrNull(15)?.toIntOrNull() ?: 0,
                nice = rest.getOrNull(16)?.toIntOrNull() ?: 0,
                policy = rest.getOrNull(38)?.toIntOrNull() ?: 0,
            )
        }
    }

    /** Shannon entropy in bits of the distribution of [items]. */
    fun <T> entropy(items: Collection<T>): Double {
        if (items.isEmpty()) return 0.0
        val n = items.size.toDouble()
        return items.groupingBy { it }.eachCount().values.sumOf { c ->
            val p = c / n
            -p * ln(p) / ln(2.0)
        }
    }
}
