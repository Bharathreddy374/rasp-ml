package com.example.demo.features.probes

import android.content.Context
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.support.measured
import com.example.demo.features.probes.support.unknown
import org.json.JSONObject

/**
 * Bridge to libtrustprobe (app/src/main/cpp/trustprobe.c). The native report is taken once per
 * scan ([begin]) and turned into catalogue signals on request ([signal]). If the library cannot
 * load, every native signal is reported as unknown.
 */
object NativeProbes {

    private val loaded: Boolean = try {
        System.loadLibrary("trustprobe")
        true
    } catch (_: Throwable) {
        false
    }

    @JvmStatic private external fun report(): String?
    @JvmStatic private external fun nop()

    @Volatile private var data: JSONObject? = null
    @Volatile private var jniRoundTripNs: Long? = null
    @Volatile private var appDirs: List<String> = emptyList()

    private val PROLOGUE = listOf(
        "F146" to "open", "F147" to "read", "F148" to "stat", "F149" to "access", "F150" to "fopen",
        "F151" to "ptrace", "F152" to "dlopen", "F153" to "mmap", "F154" to "syscall",
    )

    /** Runs the native probes for this scan. Call before any [signal]. */
    fun begin(context: Context) {
        data = null
        jniRoundTripNs = null
        val info = context.applicationInfo
        appDirs = listOfNotNull(info.nativeLibraryDir, info.sourceDir) + (info.splitSourceDirs?.toList() ?: emptyList())
        if (!loaded) return
        data = try {
            report()?.let { JSONObject(it) }
        } catch (_: Throwable) {
            null
        }
        jniRoundTripNs = try {
            repeat(16) { nop() }  // warm up
            LongArray(64) { val t = System.nanoTime(); nop(); System.nanoTime() - t }.sorted()[32]
        } catch (_: Throwable) {
            null
        }
    }

    /** The signal for [id] if it is a native probe, else null. */
    fun signal(id: String, name: String): SignalResult? {
        if (id !in IDS) return null
        val d = data ?: return unknown(id, name, if (loaded) "native probe report failed" else "native probe library not loaded")
        return try {
            build(id, name, d)
        } catch (_: Exception) {
            unknown(id, name, "native value missing")
        }
    }

    private val IDS = setOf("F039", "F040", "F155", "F156", "F157", "F159", "F163", "F210", "F213", "F215",
        "F219", "F220", "F360", "F368") + PROLOGUE.map { it.first }

    private fun alertIf(n: Long) = if (n > 0) RiskLevel.ALERT else RiskLevel.SAFE

    private fun build(id: String, name: String, d: JSONObject): SignalResult {
        PROLOGUE.firstOrNull { it.first == id }?.let { (_, fn) ->
            val diff = d.getJSONObject("prologue").getLong(fn)
            if (diff < 0) return unknown(id, name, "$fn code or its library file not readable")
            return measured(id, name, if (diff == 0L) "Matches file on disk" else "$diff of 16 bytes patched", diff, alertIf(diff),
                "First 16 bytes of $fn() in memory vs the same bytes in the library file it was mapped from (inline hook check).")
        }
        return when (id) {
            "F039" -> {
                val hits = d.getJSONArray("su_svc")
                val list = (0 until hits.length()).map { hits.getString(it) }
                measured(id, name, if (list.isEmpty()) "None found" else list.joinToString(), list.size, alertIf(list.size.toLong()),
                    "Root paths checked with a raw faccessat syscall that bypasses libc hooks.")
            }
            "F040" -> d.getLong("su_disagree").let {
                measured(id, name, if (it == 0L) "libc and syscall agree" else "$it paths disagree", it, alertIf(it),
                    "Root paths where libc access() and the raw syscall give different answers (a hiding hook in libc).")
            }
            "F155" -> {
                val p = d.getJSONObject("prologue")
                val values = PROLOGUE.map { p.getLong(it.second) }
                if (values.all { it < 0 }) return unknown(id, name, "no libc code readable")
                val patched = values.count { it > 0 }.toLong()
                measured(id, name, "$patched of ${values.count { it >= 0 }} functions patched", patched, alertIf(patched),
                    "libc / libdl entry points whose code differs from the file on disk.")
            }
            "F156" -> d.getLong("got_mismatch").let {
                measured(id, name, "$it of ${d.getInt("got_checked")} GOT entries redirected", it, alertIf(it),
                    "This library's imported function pointers vs libc's own symbols (PLT/GOT hook check).")
            }
            "F157" -> d.getLong("got_outside").let {
                measured(id, name, "$it pointing outside libc", it, alertIf(it),
                    "Imported libc functions whose resolved address lies outside libc.")
            }
            "F159" -> d.getLong("svc_libc_diff").let {
                measured(id, name, if (it == 0L) "No discrepancies" else "$it discrepancies", it, alertIf(it),
                    "getpid, getuid and file checks through libc vs raw syscalls.")
            }
            "F163" -> d.getLong("jni_outside").let {
                measured(id, name, "$it of ${d.getInt("jni_checked")} JNI functions outside libart", it, alertIf(it),
                    "JNIEnv function table entries must all point into the ART runtime.")
            }
            "F210" -> {
                val libc = d.getLong("getpid_libc_ns")
                val svc = d.getLong("getpid_svc_ns")
                val ratio = if (svc > 0) Math.round(libc.toDouble() / svc * 1000) / 1000.0 else 0.0
                measured(id, name, "$ratio", ratio, details = "Median getpid() through libc ($libc ns) vs raw syscall ($svc ns).")
            }
            "F213" -> d.getLong("getpid_svc_ns").let {
                measured(id, name, "$it ns", it, details = "Median raw getpid syscall round-trip.")
            }
            "F215" -> jniRoundTripNs?.let {
                measured(id, name, "$it ns", it, details = "Median Kotlin -> empty native method -> Kotlin call.")
            } ?: unknown(id, name, "JNI timing failed")
            "F219" -> d.getLong("mmap_ns").let {
                measured(id, name, "$it ns", it, details = "Median anonymous 4 KB mmap + munmap.")
            }
            "F220" -> d.getLong("dlsym_ns").let {
                measured(id, name, "$it ns", it, details = "Median dlsym(libc, \"open\").")
            }
            "F360" -> d.getLong("own_text_diff").let {
                if (it < 0) unknown(id, name, "own code mapping not readable")
                else measured(id, name, if (it == 0L) "Matches file (${d.optLong("own_text_bytes")} bytes)" else "$it bytes patched",
                    it, alertIf(it), "This app's native probe code in memory vs the file it was loaded from.")
            }
            "F368" -> {
                val path = d.optString("own_path")
                if (path.isEmpty()) return unknown(id, name, "own library mapping not found")
                val ok = appDirs.any { dir -> path.startsWith(dir) }
                measured(id, name, if (ok) "Loaded from the app's own install" else "Loaded from $path", ok,
                    if (ok) RiskLevel.SAFE else RiskLevel.ALERT,
                    "Where the native probe library was mapped from (a swapped library loads from elsewhere).")
            }
            else -> unknown(id, name, "not a native probe")
        }
    }
}
