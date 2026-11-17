package com.example.demo.features.probes.support

import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult

/** Catalogue category for an ID, from the ranges declared on [SignalCategory]. */
fun categoryOf(id: String): SignalCategory {
    val n = id.drop(1).toInt()
    return SignalCategory.entries.first { cat ->
        val (lo, hi) = cat.range.split("-").map { it.trim().drop(1).toInt() }
        n in lo..hi
    }
}

/** A measured signal: [raw] is the typed value the backend receives. */
fun measured(
    id: String, name: String, value: String, raw: Any?,
    risk: RiskLevel = RiskLevel.INFO, details: String,
) = SignalResult(
    id = id, name = name, category = categoryOf(id), value = value,
    raw = raw, riskLevel = risk, details = details,
)

/**
 * No measurement: the probe needs native code, a backend baseline, UI capture, or the data
 * is not observable by an unprivileged app. Sent as "unknown", never as clean.
 */
fun unknown(id: String, name: String, why: String) = SignalResult(
    id = id, name = name, category = categoryOf(id), value = "Not measured: $why",
    riskLevel = RiskLevel.INFO, details = why, implemented = false,
)

/** Checked on the backend from data it already has; the phone reports nothing. */
fun backendChecked(id: String, name: String, how: String) = SignalResult(
    id = id, name = name, category = categoryOf(id), value = "Checked by backend",
    riskLevel = RiskLevel.INFO, source = CollectionSource.SERVER_ONLY, details = how,
)

const val NEEDS_NATIVE = "needs the native (NDK) probe library"
const val NEEDS_COHORT = "needs a per-device-model baseline on the backend"
const val NEEDS_UI = "needs touch/window capture inside the app's own screens"
const val NOT_OBSERVABLE = "not observable by an unprivileged app on current Android"
