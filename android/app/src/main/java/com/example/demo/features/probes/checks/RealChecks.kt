package com.example.demo.features.probes.checks

import android.content.Context
import com.example.demo.features.model.SignalResult
import com.example.demo.features.probes.NativeProbes
import com.example.demo.features.probes.support.unknown

/**
 * Entry point for checks that replaced constant placeholders inside the original probe files.
 * Each call site passes its catalogue ID and name; a check that throws becomes unknown.
 */
object RealChecks {
    fun get(id: String, name: String, context: Context?): SignalResult = try {
        NativeProbes.signal(id, name) ?: (context?.let { AppChecks.get(id, name, it) ?: DeviceChecks.get(id, name, it) ?: RuntimeChecks.get(id, name, it) }
            ?: ProcContextChecks.get(id, name, context))
            ?: unknown(id, name, "no implementation registered")
    } catch (_: Throwable) {
        unknown(id, name, "check failed on this device")
    }
}
