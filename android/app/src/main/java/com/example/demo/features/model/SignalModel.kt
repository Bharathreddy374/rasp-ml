package com.example.demo.features.model

enum class RiskLevel {
    SAFE,
    INFO,
    SUSPICIOUS,
    ALERT
}

enum class CollectionSource(
    val label: String,
    val badgeColorHex: Long,
    val summary: String,
    val backendRequirement: String
) {
    DEVICE_ONLY(
        label = "Device SDK",
        badgeColorHex = 0xFF2E7D32, // Green
        summary = "100% retrievable directly on device without any backend.",
        backendRequirement = "No backend required. Runs entirely on phone hardware, kernel, and Android runtime."
    ),
    HYBRID(
        label = "Hybrid (Device + Server Verify)",
        badgeColorHex = 0xFF1565C0, // Blue
        summary = "Collected on device, verified on backend.",
        backendRequirement = "Backend required to cryptographically verify hardware certs against Google Root CA, decrypt Play Integrity JWE tokens, or compare hashes against CI manifests."
    ),
    SERVER_ONLY(
        label = "Server-Side Only",
        badgeColorHex = 0xFF6A1B9A, // Purple
        summary = "Observed at server edge or computed in fraud database.",
        backendRequirement = "Strict backend requirement. Observed at network edge (IP/ASN/JA3), aggregated across 30 days in feature store, or computed in graph databases (fraud clusters)."
    )
}

enum class SignalCategory(val displayName: String, val range: String, val defaultSource: CollectionSource) {
    ATTESTATION("Attestation & Keystore", "F001 - F015", CollectionSource.HYBRID),
    DEVICE_STATIC("Device & Build Properties", "F016 - F036", CollectionSource.DEVICE_ONLY),
    ROOT_SELINUX("Root & SELinux Artefacts", "F037 - F054", CollectionSource.DEVICE_ONLY),
    MOUNT_KERNEL("Mount Table & Kernel", "F055 - F075", CollectionSource.DEVICE_ONLY),
    APP_INTEGRITY("App & Package Integrity", "F076 - F115", CollectionSource.DEVICE_ONLY),
    RUNTIME_HOOKING("Runtime, Debug & Hooks", "F116 - F175", CollectionSource.DEVICE_ONLY),
    MEMORY_PROCFS("Memory & Procfs", "F176 - F205", CollectionSource.DEVICE_ONLY),
    TIMING_PROBES("Timing Side-Channels", "F206 - F230", CollectionSource.DEVICE_ONLY),
    SENSOR_TOUCH("Sensors, Touch & Battery", "F231 - F270", CollectionSource.DEVICE_ONLY),
    RISKY_CONTEXT("Risky Context & Settings", "F271 - F285", CollectionSource.DEVICE_ONLY),
    NETWORK_SERVER("Network & Edge Telemetry", "F286 - F305", CollectionSource.SERVER_ONLY),
    HISTORY_GRAPH("History & Graph Reputation", "F306 - F350", CollectionSource.SERVER_ONLY),
    PROBE_HEALTH("Probe Health & Integrity", "F351 - F370", CollectionSource.HYBRID)
}

data class SignalResult(
    val id: String,
    val name: String,
    val category: SignalCategory,
    /** Human-readable text for the UI only. Never parsed by the backend. */
    val value: String,
    val riskLevel: RiskLevel = RiskLevel.SAFE,
    val source: CollectionSource = category.defaultSource,
    val details: String = "",
    /**
     * Typed value sent to the backend (Boolean, Int, Long, Double or a short String).
     * When null, the wire format falls back to the numeric part of [value] or the short text.
     */
    val raw: Any? = null,
    /**
     * False when the probe does not measure anything yet (constant placeholder).
     * Such signals are sent as "unknown", never as clean evidence.
     */
    val implemented: Boolean = true
)
