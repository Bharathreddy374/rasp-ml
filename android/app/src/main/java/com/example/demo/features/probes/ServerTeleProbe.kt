package com.example.demo.features.probes

import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult

/**
 * Catalogue groups 9-11 (F286 - F350) are observed or computed by the backend:
 * IP / ASN / TLS at the edge, history in the feature store, graph offline.
 *
 * The phone cannot know these values, so it never reports them. These rows exist only
 * so the catalogue screen lists all 370 signals; they are excluded from the payload
 * (see TrustPayload) and the backend's response says which ones it computed.
 */
object ServerTeleProbe {

    private val NETWORK = listOf(
        "F286" to "ip_asn", "F287" to "ip_asn_type", "F288" to "ip_country",
        "F289" to "ip_vs_sim_country", "F290" to "ip_vs_timezone", "F291" to "ip_vs_locale",
        "F292" to "vpn_proxy_flag", "F293" to "tor_exit_flag", "F294" to "datacenter_ip_flag",
        "F295" to "ip_reputation_score", "F296" to "tls_ja3_hash", "F297" to "tls_ja3_vs_cohort",
        "F298" to "http_header_order_hash", "F299" to "user_agent_vs_build", "F300" to "dns_resolver_class",
        "F301" to "network_type", "F302" to "rtt_ms", "F303" to "wifi_vs_cell_switches",
        "F304" to "ip_changes_in_session", "F305" to "request_timing_regularity",
    )

    private val HISTORY = listOf(
        "F306" to "patch_level_regressed", "F307" to "verified_boot_regressed",
        "F308" to "bootloader_state_changed", "F309" to "fingerprint_changed",
        "F310" to "boot_count_reset_unexpected", "F311" to "uptime_vs_session_gap",
        "F312" to "os_version_downgrade", "F313" to "kernel_version_changed",
        "F314" to "sdk_version_changed", "F315" to "app_version_regression",
        "F316" to "attest_key_rotation_freq", "F317" to "attest_key_age_days",
        "F318" to "attest_chain_changed", "F319" to "key_reinstall_regen",
        "F320" to "distinct_attest_keys_per_install", "F321" to "key_created_in_session",
        "F322" to "devices_per_account_30d", "F323" to "accounts_per_device_30d",
        "F324" to "installs_per_key_24h", "F325" to "new_install_velocity",
        "F326" to "reinstall_count_30d", "F327" to "login_from_new_device_flag",
        "F328" to "payee_adds_in_session", "F329" to "time_since_install",
        "F330" to "max_level_last_30d", "F331" to "level4plus_count_30d",
        "F332" to "rule_hits_last_30d", "F333" to "anomaly_pct_trend",
        "F334" to "step_up_failures_30d", "F335" to "prior_fraud_flag",
    )

    private val GRAPH = listOf(
        "F336" to "accounts_per_attest_cert_serial_24h", "F337" to "devices_per_attest_intermediate",
        "F338" to "devices_per_sensor_signature", "F339" to "devices_per_ip24",
        "F340" to "devices_per_asn_24h", "F341" to "devices_per_payee",
        "F342" to "shared_payee_count", "F343" to "community_id_size",
        "F344" to "community_emulator_share", "F345" to "community_new_install_share",
        "F346" to "community_shared_payee_share", "F347" to "community_reputation_score",
        "F348" to "entity_age_days", "F349" to "graph_component_size", "F350" to "farm_cluster_score",
    )

    fun collect(): List<SignalResult> {
        val list = mutableListOf<SignalResult>()
        fun add(pairs: List<Pair<String, String>>, category: SignalCategory, where: String) {
            for ((id, name) in pairs) {
                list.add(
                    SignalResult(
                        id = id,
                        name = name,
                        category = category,
                        value = "Computed by backend",
                        riskLevel = RiskLevel.INFO,
                        source = CollectionSource.SERVER_ONLY,
                        details = "$where. Not collected on the device and not sent in the payload."
                    )
                )
            }
        }
        add(NETWORK, SignalCategory.NETWORK_SERVER, "Observed at the server edge from the request itself")
        add(HISTORY, SignalCategory.HISTORY_GRAPH, "Computed from this install's history in the feature store")
        add(GRAPH, SignalCategory.HISTORY_GRAPH, "Computed offline across all devices (graph)")
        return list
    }
}
