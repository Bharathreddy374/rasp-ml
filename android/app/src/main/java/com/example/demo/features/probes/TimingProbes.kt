package com.example.demo.features.probes

import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.NEEDS_COHORT
import com.example.demo.features.probes.support.NEEDS_NATIVE
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import java.util.UUID
import java.util.concurrent.CountDownLatch
import kotlin.math.sqrt

/**
 * Catalogue group 6 (F206 - F230): timing side-channels, all measured here.
 *
 * Hooks that hide root or instrument the app slow down the calls they intercept. Each
 * hidden-vs-control ratio times the same syscall on paths root hiders target and on random
 * missing paths in the same directories, interleaved, median of 32 trials. On a clean
 * device the ratio is close to 1. Values are raw; the backend compares per device model.
 *
 * F221 / F223 / F224 (scan and attestation latency) are added by the scanner, which owns
 * those timings. Calls that need our own native library are unknown until it exists.
 */
object TimingProbes {

    private const val TRIALS = 32
    private val HIDDEN = listOf(
        "/system/xbin/su", "/system/bin/su", "/sbin/su", "/data/adb/magisk", "/data/adb/ksu",
        "/data/adb/ap", "/debug_ramdisk", "/sbin/.magisk", "/data/local/tmp/frida-server",
    )

    private fun control(): List<String> = HIDDEN.map { it.substringBeforeLast('/') + "/" + UUID.randomUUID().toString().take(8) }

    private fun median(xs: LongArray): Long = xs.sorted()[xs.size / 2]

    private fun native(id: String, name: String) = NativeProbes.signal(id, name) ?: unknown(id, name, NEEDS_NATIVE)

    /** Median latency of [op] over [paths], interleaved with [ctrl] to cancel drift. Returns (hidden, control). */
    private fun pairTiming(paths: List<String>, ctrl: List<String>, op: (String) -> Unit): Pair<Long, Long> {
        val h = LongArray(TRIALS)
        val c = LongArray(TRIALS)
        for (i in 0 until TRIALS) {
            val hp = paths[i % paths.size]
            val cp = ctrl[i % ctrl.size]
            var t = System.nanoTime(); runCatching { op(hp) }; h[i] = System.nanoTime() - t
            t = System.nanoTime(); runCatching { op(cp) }; c[i] = System.nanoTime() - t
        }
        return median(h) to median(c)
    }

    private fun ratio(a: Long, b: Long): Double = if (b <= 0) 0.0 else Math.round(a.toDouble() / b * 1000) / 1000.0

    fun collect(): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        val ctrl = control()
        // warm up class loading and the dentry cache so the first trials do not skew medians
        HIDDEN.forEach { runCatching { Os.access(it, OsConstants.F_OK) } }
        ctrl.forEach { runCatching { Os.access(it, OsConstants.F_OK) } }

        val (openH, openC) = pairTiming(HIDDEN, ctrl) { Os.close(Os.open(it, OsConstants.O_RDONLY, 0)) }
        val (accH, accC) = pairTiming(HIDDEN, ctrl) { Os.access(it, OsConstants.F_OK) }
        val (statH, statC) = pairTiming(HIDDEN, ctrl) { Os.stat(it) }
        val ratioDetail = "Median latency on root-hider target paths divided by random missing paths in the same " +
            "directories ($TRIALS interleaved trials). Near 1.0 on a clean device."
        list.add(measured("F206", "openat_hidden_vs_control_ratio", "${ratio(openH, openC)}", ratio(openH, openC), details = ratioDetail))
        list.add(measured("F207", "access_hidden_vs_control_ratio", "${ratio(accH, accC)}", ratio(accH, accC), details = ratioDetail))
        list.add(measured("F208", "stat_hidden_vs_control_ratio", "${ratio(statH, statC)}", ratio(statH, statC), details = ratioDetail))

        val readlink = LongArray(TRIALS) { val t = System.nanoTime(); runCatching { Os.readlink("/proc/self/exe") }; System.nanoTime() - t }
        list.add(measured("F209", "readlink_proc_exe_ns", "${median(readlink)} ns", median(readlink),
            details = "Median latency of readlink(/proc/self/exe)."))
        list.add(native("F210", "getpid_libc_vs_syscall_ratio"))

        val open = LongArray(TRIALS) {
            val t = System.nanoTime()
            runCatching { Os.close(Os.open("/proc/self/stat", OsConstants.O_RDONLY, 0)) }
            System.nanoTime() - t
        }
        list.add(measured("F211", "libc_open_latency_ns", "${median(open)} ns", median(open),
            details = "Median open+close of /proc/self/stat through libcore -> libc."))

        val read = runCatching {
            val fd = Os.open("/proc/self/cmdline", OsConstants.O_RDONLY, 0)
            val buf = ByteArray(64)
            try {
                LongArray(TRIALS) { val t = System.nanoTime(); Os.pread(fd, buf, 0, buf.size, 0); System.nanoTime() - t }
            } finally {
                Os.close(fd)
            }
        }.getOrNull()
        list.add(
            if (read != null) measured("F212", "libc_read_latency_ns", "${median(read)} ns", median(read),
                details = "Median 64-byte pread of /proc/self/cmdline.")
            else unknown("F212", "libc_read_latency_ns", "read probe failed")
        )
        list.add(native("F213", "syscall_svc_latency_ns"))

        list.add(measured("F214", "openat_hidden_median_ns", "$openH ns", openH,
            details = "Median open() latency on root-hider target paths."))
        list.add(native("F215", "jni_roundtrip_ns"))
        list.add(unknown("F216", "jni_roundtrip_zscore", NEEDS_COHORT))

        val refl = runCatching {
            val m = String::class.java.getMethod("length")
            LongArray(TRIALS) { val t = System.nanoTime(); m.invoke("probe"); System.nanoTime() - t }
        }.getOrNull()
        list.add(
            if (refl != null) measured("F217", "java_reflection_call_ns", "${median(refl)} ns", median(refl),
                details = "Median Method.invoke latency.")
            else unknown("F217", "java_reflection_call_ns", "reflection probe failed")
        )

        val threadStart = LongArray(8) {
            val latch = CountDownLatch(1)
            var started = 0L
            val t0 = System.nanoTime()
            Thread { started = System.nanoTime(); latch.countDown() }.start()
            latch.await()
            started - t0
        }
        list.add(measured("F218", "thread_start_latency_ns", "${median(threadStart)} ns", median(threadStart),
            details = "Median delay from Thread.start() to the first instruction of the new thread (8 trials)."))
        list.add(native("F219", "mmap_latency_ns"))
        list.add(native("F220", "dlsym_latency_ns"))
        list.add(unknown("F222", "probe_duration_zscore", NEEDS_COHORT))
        list.add(unknown("F225", "pi_token_latency_ms", "Play Integrity is not integrated"))

        val nano0 = System.nanoTime()
        val elapsed0 = SystemClock.elapsedRealtimeNanos()
        Thread.sleep(2)
        val drift = kotlin.math.abs((System.nanoTime() - nano0) - (SystemClock.elapsedRealtimeNanos() - elapsed0))
        list.add(measured("F226", "monotonic_vs_wall_drift", "$drift ns", drift,
            details = "Difference between System.nanoTime and elapsedRealtimeNanos over a 2 ms sleep."))

        val deltas = LongArray(2000)
        var prev = System.nanoTime()
        for (i in deltas.indices) { val now = System.nanoTime(); deltas[i] = now - prev; prev = now }
        val mean = deltas.average()
        val sd = sqrt(deltas.sumOf { (it - mean) * (it - mean) } / deltas.size)
        val resolution = deltas.filter { it > 0 }.minOrNull() ?: 0L
        list.add(measured("F227", "clock_gettime_jitter", "${sd.toLong()} ns stdev", Math.round(sd),
            details = "Standard deviation of 2000 back-to-back clock reads; virtualised clocks are noisier."))
        list.add(measured("F228", "timer_resolution_ns", "$resolution ns", resolution,
            details = "Smallest non-zero step between consecutive clock reads."))

        val loop = LongArray(8) {
            val t = System.nanoTime(); var acc = 0L; for (i in 0..10000) acc += i.toLong() xor (acc shr 3); System.nanoTime() - t + (acc and 0L)
        }
        list.add(measured("F229", "loop_calibration_ns", "${median(loop)} ns (10k iter)", median(loop),
            details = "Median time of a fixed 10k-iteration integer loop."))

        val mem = IntArray(1 shl 18)
        val walks = LongArray(16) {
            val t = System.nanoTime(); var s = 0; var i = 0
            while (i < mem.size) { s += mem[i]; i += 16 }
            System.nanoTime() - t + (s and 0)
        }
        val wMean = walks.average()
        val cv = if (wMean > 0) sqrt(walks.sumOf { (it - wMean) * (it - wMean) } / walks.size) / wMean else 0.0
        list.add(measured("F230", "cache_timing_variance", "CV ${"%.3f".format(cv)}", Math.round(cv * 1000) / 1000.0,
            risk = RiskLevel.INFO, details = "Coefficient of variation of 16 strided walks over 1 MB."))
        return list
    }
}
