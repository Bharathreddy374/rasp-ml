package com.example.demo.features.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FilterChipDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.demo.features.model.CollectionSource
import com.example.demo.features.model.RiskLevel
import com.example.demo.features.model.SignalCategory
import com.example.demo.features.model.SignalResult
import com.example.demo.features.network.ApiResponse
import com.example.demo.features.network.BackendApiClient
import com.example.demo.features.network.CollectPayload
import com.example.demo.features.scanner.FeatureCatalogueScanner
import com.example.demo.features.scanner.ScanSummary
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FeatureCatalogueScreen() {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var scanSummary by remember { mutableStateOf<ScanSummary?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var searchQuery by remember { mutableStateOf("") }
    var selectedCategory by remember { mutableStateOf<SignalCategory?>(null) }
    var selectedRiskFilter by remember { mutableStateOf<RiskLevel?>(null) }
    var selectedSourceFilter by remember { mutableStateOf<CollectionSource?>(null) }

    var showBackendInfoDialog by remember { mutableStateOf(false) }
    var showSendApiDialog by remember { mutableStateOf(false) }

    fun runScan() {
        isScanning = true
        scope.launch {
            scanSummary = FeatureCatalogueScanner.scanAll(context)
            isScanning = false
        }
    }

    LaunchedEffect(Unit) {
        runScan()
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text(
                            text = "Feature Catalogue",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            text = "370 Signals · Client vs Backend Audit",
                            style = MaterialTheme.typography.labelMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                actions = {
                    OutlinedButton(
                        onClick = { showBackendInfoDialog = true },
                        modifier = Modifier.padding(end = 4.dp),
                        contentPadding = ButtonDefaults.TextButtonContentPadding
                    ) {
                        Text("Backend?", fontSize = 12.sp)
                    }

                    Button(
                        onClick = { runScan() },
                        enabled = !isScanning,
                        modifier = Modifier.padding(end = 8.dp)
                    ) {
                        Text(if (isScanning) "Scanning..." else "Re-Scan")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
        ) {
            if (isScanning && scanSummary == null) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        CircularProgressIndicator()
                        Spacer(modifier = Modifier.height(16.dp))
                        Text(
                            text = "Scanning device integrity & telemetry signals...",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            } else {
                val summary = scanSummary
                if (summary != null) {
                    // Summary Header Card
                    SummaryHeaderCard(
                        summary = summary,
                        selectedRisk = selectedRiskFilter,
                        onRiskSelected = { risk ->
                            selectedRiskFilter = if (selectedRiskFilter == risk) null else risk
                        },
                        onOpenBackendInfo = { showBackendInfoDialog = true },
                        onOpenSendApi = { showSendApiDialog = true },
                        onExportJson = {
                            val json = CollectPayload.build(context, summary, "transfer")
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = ClipData.newPlainText("Device Features JSON", json)
                            clipboard.setPrimaryClip(clip)
                            Toast.makeText(context, "rasp_collect_v2 payload copied to clipboard", Toast.LENGTH_SHORT).show()
                        },
                        onShare = {
                            val json = CollectPayload.build(context, summary, "transfer")
                            val sendIntent = Intent().apply {
                                action = Intent.ACTION_SEND
                                putExtra(Intent.EXTRA_TEXT, json)
                                type = "application/json"
                            }
                            context.startActivity(Intent.createChooser(sendIntent, "Share Feature Catalogue JSON"))
                        }
                    )

                    // Source Filter Chips Row (Device vs Hybrid vs Server)
                    SourceFilterChipsRow(
                        summary = summary,
                        selectedSource = selectedSourceFilter,
                        onSourceSelected = { src ->
                            selectedSourceFilter = if (selectedSourceFilter == src) null else src
                        }
                    )

                    // Search Field
                    OutlinedTextField(
                        value = searchQuery,
                        onValueChange = { searchQuery = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 16.dp, vertical = 6.dp),
                        placeholder = { Text("Search by ID (e.g. F037, F124) or signal name...") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp)
                    )

                    // Categories Filter Row
                    val scrollState = rememberScrollState()
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .horizontalScroll(scrollState)
                            .padding(horizontal = 16.dp, vertical = 4.dp),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        FilterChip(
                            selected = selectedCategory == null,
                            onClick = { selectedCategory = null },
                            label = { Text("All Categories (${summary.signals.size})") }
                        )

                        SignalCategory.entries.forEach { cat ->
                            val count = summary.signals.count { it.category == cat }
                            FilterChip(
                                selected = selectedCategory == cat,
                                onClick = {
                                    selectedCategory = if (selectedCategory == cat) null else cat
                                },
                                label = { Text("${cat.displayName} ($count)") }
                            )
                        }
                    }

                    // Filtered List
                    val filteredSignals = summary.signals.filter { s ->
                        val matchesSearch = searchQuery.isBlank() ||
                                s.id.contains(searchQuery, ignoreCase = true) ||
                                s.name.contains(searchQuery, ignoreCase = true) ||
                                s.value.contains(searchQuery, ignoreCase = true) ||
                                s.details.contains(searchQuery, ignoreCase = true)

                        val matchesCategory = selectedCategory == null || s.category == selectedCategory
                        val matchesRisk = selectedRiskFilter == null || s.riskLevel == selectedRiskFilter
                        val matchesSource = selectedSourceFilter == null || s.source == selectedSourceFilter

                        matchesSearch && matchesCategory && matchesRisk && matchesSource
                    }

                    Text(
                        text = "Showing ${filteredSignals.size} of ${summary.signals.size} signals",
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                    )

                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(filteredSignals, key = { it.id }) { signal ->
                            SignalItemCard(signal = signal)
                        }
                        item {
                            Spacer(modifier = Modifier.height(24.dp))
                        }
                    }
                }
            }
        }
    }

    // Backend Requirements Explanation Dialog
    if (showBackendInfoDialog) {
        BackendRequirementDialog(onDismiss = { showBackendInfoDialog = false })
    }

    // Send to Backend API Dialog
    if (showSendApiDialog && scanSummary != null) {
        SendToBackendDialog(
            onScanned = { fresh -> scanSummary = fresh },
            onDismiss = { showSendApiDialog = false }
        )
    }
}

@Composable
fun SourceFilterChipsRow(
    summary: ScanSummary,
    selectedSource: CollectionSource?,
    onSourceSelected: (CollectionSource) -> Unit
) {
    val scrollState = rememberScrollState()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(scrollState)
            .padding(horizontal = 16.dp, vertical = 2.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = selectedSource == null,
            onClick = { onSourceSelected(CollectionSource.DEVICE_ONLY) }, // dummy toggle
            label = { Text("All Sources") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = MaterialTheme.colorScheme.secondaryContainer
            )
        )

        FilterChip(
            selected = selectedSource == CollectionSource.DEVICE_ONLY,
            onClick = { onSourceSelected(CollectionSource.DEVICE_ONLY) },
            label = { Text("📱 Device SDK (${summary.deviceOnlyCount})") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFF2E7D32).copy(alpha = 0.2f),
                selectedLabelColor = Color(0xFF1B5E20)
            )
        )

        FilterChip(
            selected = selectedSource == CollectionSource.HYBRID,
            onClick = { onSourceSelected(CollectionSource.HYBRID) },
            label = { Text("☁️ Hybrid (${summary.hybridCount})") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFF1565C0).copy(alpha = 0.2f),
                selectedLabelColor = Color(0xFF0D47A1)
            )
        )

        FilterChip(
            selected = selectedSource == CollectionSource.SERVER_ONLY,
            onClick = { onSourceSelected(CollectionSource.SERVER_ONLY) },
            label = { Text("🖥️ Server Only (${summary.serverOnlyCount})") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFF6A1B9A).copy(alpha = 0.2f),
                selectedLabelColor = Color(0xFF4A148C)
            )
        )
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun SummaryHeaderCard(
    summary: ScanSummary,
    selectedRisk: RiskLevel?,
    onRiskSelected: (RiskLevel) -> Unit,
    onOpenBackendInfo: () -> Unit,
    onOpenSendApi: () -> Unit,
    onExportJson: () -> Unit,
    onShare: () -> Unit
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.6f)
        ),
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column {
                    Text(
                        text = "Telemetry Scan Complete",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = "${summary.signals.size} Signals Collected in ${summary.scanDurationMs}ms",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    if (summary.notImplementedCount > 0 || summary.failedGroups.isNotEmpty()) {
                        Text(
                            text = "${summary.notImplementedCount} not implemented (sent as unknown)" +
                                if (summary.failedGroups.isNotEmpty()) " · failed: ${summary.failedGroups.joinToString()}" else "",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color(0xFF757575)
                        )
                    }
                }

                // Send to API Primary Button
                Button(
                    onClick = onOpenSendApi,
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Send to API", fontSize = 12.sp, fontWeight = FontWeight.Bold)
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            // Action row: Copy JSON, Share, Backend Requirements
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedButton(
                    onClick = onOpenBackendInfo,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Backend Info", fontSize = 11.sp)
                }

                OutlinedButton(
                    onClick = onExportJson,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Copy JSON", fontSize = 11.sp)
                }

                OutlinedButton(
                    onClick = onShare,
                    modifier = Modifier.weight(1f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text("Share", fontSize = 11.sp)
                }
            }

            Spacer(modifier = Modifier.height(12.dp))
            HorizontalDivider()
            Spacer(modifier = Modifier.height(12.dp))

            // Badges row
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                StatBadge(
                    label = "SAFE",
                    count = summary.safeCount,
                    color = Color(0xFF2E7D32),
                    isSelected = selectedRisk == RiskLevel.SAFE,
                    onClick = { onRiskSelected(RiskLevel.SAFE) }
                )
                StatBadge(
                    label = "INFO",
                    count = summary.infoCount,
                    color = Color(0xFF1565C0),
                    isSelected = selectedRisk == RiskLevel.INFO,
                    onClick = { onRiskSelected(RiskLevel.INFO) }
                )
                StatBadge(
                    label = "SUSPICIOUS",
                    count = summary.suspiciousCount,
                    color = Color(0xFFEF6C00),
                    isSelected = selectedRisk == RiskLevel.SUSPICIOUS,
                    onClick = { onRiskSelected(RiskLevel.SUSPICIOUS) }
                )
                StatBadge(
                    label = "ALERT",
                    count = summary.alertCount,
                    color = Color(0xFFC62828),
                    isSelected = selectedRisk == RiskLevel.ALERT,
                    onClick = { onRiskSelected(RiskLevel.ALERT) }
                )
            }
        }
    }
}

@Composable
fun StatBadge(
    label: String,
    count: Int,
    color: Color,
    isSelected: Boolean,
    onClick: () -> Unit
) {
    Surface(
        onClick = onClick,
        shape = RoundedCornerShape(8.dp),
        color = if (isSelected) color else color.copy(alpha = 0.12f),
        border = if (isSelected) null else androidx.compose.foundation.BorderStroke(1.dp, color.copy(alpha = 0.3f))
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .clip(CircleShape)
                    .background(if (isSelected) Color.White else color)
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
                text = "$label: $count",
                style = MaterialTheme.typography.labelMedium,
                fontWeight = FontWeight.Bold,
                color = if (isSelected) Color.White else color
            )
        }
    }
}

@Composable
fun SignalItemCard(signal: SignalResult) {
    var expanded by remember { mutableStateOf(false) }

    val riskColor = if (!signal.implemented) Color(0xFF757575) else when (signal.riskLevel) {
        RiskLevel.SAFE -> Color(0xFF2E7D32)
        RiskLevel.INFO -> Color(0xFF1565C0)
        RiskLevel.SUSPICIOUS -> Color(0xFFEF6C00)
        RiskLevel.ALERT -> Color(0xFFC62828)
    }

    val sourceColor = Color(signal.source.badgeColorHex)

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { expanded = !expanded },
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        border = androidx.compose.foundation.BorderStroke(
            1.dp,
            if (signal.riskLevel == RiskLevel.ALERT || signal.riskLevel == RiskLevel.SUSPICIOUS) {
                riskColor.copy(alpha = 0.4f)
            } else {
                MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f)
            }
        )
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    // ID Badge
                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = MaterialTheme.colorScheme.primaryContainer
                    ) {
                        Text(
                            text = signal.id,
                            style = MaterialTheme.typography.labelSmall,
                            fontWeight = FontWeight.Bold,
                            fontFamily = FontFamily.Monospace,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            modifier = Modifier.padding(horizontal = 6.dp, vertical = 3.dp)
                        )
                    }

                    Spacer(modifier = Modifier.width(8.dp))

                    Text(
                        text = signal.name,
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                // Source Badge (Device / Hybrid / Server)
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = sourceColor.copy(alpha = 0.12f)
                ) {
                    Text(
                        text = signal.source.label,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = sourceColor,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            Spacer(modifier = Modifier.height(6.dp))

            // Value & Risk Row
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = signal.value,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.weight(1f)
                )

                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = riskColor.copy(alpha = 0.12f)
                ) {
                    Text(
                        text = if (signal.implemented) signal.riskLevel.name else "NOT IMPLEMENTED",
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        color = riskColor,
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp)
                    )
                }
            }

            // Category & Details
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = signal.category.displayName,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                Text(
                    text = if (expanded) "Collapse ▲" else "Details & Backend info ▼",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary
                )
            }

            AnimatedVisibility(visible = expanded) {
                Column(modifier = Modifier.padding(top = 8.dp)) {
                    HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                    Text(
                        text = signal.details,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    Surface(
                        shape = RoundedCornerShape(6.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant
                    ) {
                        Column(modifier = Modifier.padding(8.dp)) {
                            Text(
                                text = "Requirement: ${signal.source.summary}",
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold,
                                color = sourceColor
                            )
                            Text(
                                text = signal.source.backendRequirement,
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun BackendRequirementDialog(onDismiss: () -> Unit) {
    AlertDialog(
        onDismissRequest = onDismiss,
        title = {
            Text(
                text = "Backend Requirements Audit",
                fontWeight = FontWeight.Bold
            )
        },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text(
                    text = "Can all 370 features be retrieved strictly on the device?",
                    fontWeight = FontWeight.SemiBold,
                    color = MaterialTheme.colorScheme.primary
                )
                Text(
                    text = "No. In modern mobile anti-fraud & integrity architecture, signals are split into 3 tiers:",
                    style = MaterialTheme.typography.bodySmall
                )

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFF2E7D32).copy(alpha = 0.1f)
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            text = "1. 📱 Device SDK Only (~270 Signals; placeholders marked NOT IMPLEMENTED)",
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF1B5E20)
                        )
                        Text(
                            text = "100% retrieved on the phone. Includes root artefacts, su paths, Frida/Xposed hooks, SELinux mode, memory map shapes (/proc/self/maps), procfs status, sensors noise, touch dynamics, and risky settings.",
                            style = MaterialTheme.typography.bodySmall,
                            fontSize = 11.sp
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFF1565C0).copy(alpha = 0.1f)
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            text = "2. ☁️ Hybrid: Device + Server Verify (~35 Signals)",
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF0D47A1)
                        )
                        Text(
                            text = "Hardware KeyStore generates certificates & Play Integrity returns JWE tokens, but verification MUST occur on your backend server against Google's Root CA to prevent client-side bypass.",
                            style = MaterialTheme.typography.bodySmall,
                            fontSize = 11.sp
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = Color(0xFF6A1B9A).copy(alpha = 0.1f)
                ) {
                    Column(modifier = Modifier.padding(8.dp)) {
                        Text(
                            text = "3. 🖥️ Server-Side Only (65 Signals, F286-F350; never sent by the phone)",
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF4A148C)
                        )
                        Text(
                            text = "Strictly requires backend. Edge servers observe real IP, ASN, and TLS JA3 handshake. Feature Store calculates 30-day velocity (reinstalls, account churn). Graph DB detects device farms.",
                            style = MaterialTheme.typography.bodySmall,
                            fontSize = 11.sp
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(onClick = onDismiss) {
                Text("Understood")
            }
        }
    )
}

@Composable
fun SendToBackendDialog(
    onScanned: (ScanSummary) -> Unit,
    onDismiss: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()

    var collectorUrl by remember { mutableStateOf(BackendApiClient.getCollectorUrl(context)) }
    var isSending by remember { mutableStateOf(false) }
    var apiResponse by remember { mutableStateOf<ApiResponse?>(null) }

    fun send() {
        val url = collectorUrl.trim()
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            Toast.makeText(context, "Enter the full collector URL (http:// or https://)", Toast.LENGTH_SHORT).show()
            return
        }
        BackendApiClient.saveCollectorUrl(context, url)
        isSending = true
        scope.launch {
            val (fresh, response) = BackendApiClient.sendCollect(context, url)
            fresh?.let(onScanned)
            apiResponse = response
            isSending = false
        }
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(text = "Send rasp_collect_v2", fontWeight = FontWeight.Bold) },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                Text(
                    text = "Rescans and POSTs the rasp_collect_v2 payload as plain JSON to the collector. " +
                        "Unsigned: no nonce or attestation.",
                    style = MaterialTheme.typography.bodySmall
                )

                OutlinedTextField(
                    value = collectorUrl,
                    onValueChange = { collectorUrl = it },
                    label = { Text("Collector URL (full endpoint)") },
                    placeholder = { Text("https://collector.example.com/collect") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(8.dp)
                )

                if (isSending) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 12.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                        Spacer(modifier = Modifier.width(12.dp))
                        Text("Scanning and sending...", style = MaterialTheme.typography.bodyMedium)
                    }
                }

                apiResponse?.let { response -> AssessmentResultCard(response) }
            }
        },
        confirmButton = {
            Button(onClick = { send() }, enabled = !isSending) {
                Text(if (isSending) "Sending..." else "Send payload")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Close") }
        }
    )
}

@Composable
private fun AssessmentResultCard(response: ApiResponse) {
    val result = response.result
    val levelColor = when (result?.level) {
        1 -> Color(0xFF2E7D32)
        2 -> Color(0xFF1565C0)
        3 -> Color(0xFFEF6C00)
        4 -> Color(0xFFE65100)
        5 -> Color(0xFFC62828)
        else -> if (response.isSuccess) Color(0xFF2E7D32) else Color(0xFFC62828)
    }
    val small = MaterialTheme.typography.bodySmall
    val label = MaterialTheme.typography.labelSmall
    val muted = MaterialTheme.colorScheme.onSurfaceVariant

    Surface(
        shape = RoundedCornerShape(10.dp),
        color = levelColor.copy(alpha = 0.08f),
        border = androidx.compose.foundation.BorderStroke(1.dp, levelColor.copy(alpha = 0.5f))
    ) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (response.isSuccess) "Sent (HTTP ${response.statusCode})" else "Error HTTP ${response.statusCode}",
                    fontWeight = FontWeight.Bold,
                    color = if (response.isSuccess) Color(0xFF1B5E20) else Color(0xFFB71C1C)
                )
                Text(text = "${response.durationMs}ms", style = label, color = muted)
            }

            if (response.payloadBytes > 0) {
                Text(
                    text = "Payload ${"%.1f".format(response.payloadBytes / 1024.0)} KB, " +
                        "${"%.1f".format(response.wireBytes / 1024.0)} KB on the wire (gzip)" +
                        if (response.attested) " · hardware-attested" else " · unsigned",
                    style = small, fontSize = 11.sp, color = muted
                )
            }

            response.errorMessage?.let {
                Text(text = it, style = small, fontWeight = FontWeight.SemiBold, color = Color(0xFFB71C1C))
            }

            if (result == null) {
                if (response.responseBody.isNotBlank()) {
                    Text(
                        text = "Server response:\n${response.responseBody.take(500)}",
                        style = small, fontFamily = FontFamily.Monospace, fontSize = 10.sp
                    )
                }
            } else {
                HorizontalDivider()
                Surface(shape = RoundedCornerShape(8.dp), color = levelColor) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "Trust Level ${result.level}: ${result.label}",
                            fontWeight = FontWeight.Bold, color = Color.White, fontSize = 15.sp
                        )
                        Text(
                            text = result.outcome.uppercase(),
                            fontWeight = FontWeight.Bold, color = Color.White.copy(alpha = 0.9f), fontSize = 12.sp
                        )
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(text = "Rules level: ${result.rulesLevel}", style = small, fontWeight = FontWeight.SemiBold)
                    Text(text = "ML level: ${result.mlLevel ?: "off"}", style = small, fontWeight = FontWeight.SemiBold)
                }

                result.coverage?.let { c ->
                    Text(
                        text = "Signals: ${c.optInt("device_signals")} from device, " +
                            "${c.optInt("unknown")} unknown, ${c.optInt("server_signals")} computed on server",
                        style = label, color = muted
                    )
                }

                result.attestation?.let { a ->
                    Text(
                        text = "Attestation: chain ${if (a.optBoolean("chain_valid")) "valid" else "INVALID"}, " +
                            "root ${if (a.optBoolean("root_trusted")) "Google" else "UNTRUSTED"}, " +
                            "${a.optString("security_level")}, boot ${a.optString("verified_boot_state")}, " +
                            "bootloader ${if (a.optBoolean("device_locked")) "locked" else "unlocked"}",
                        style = label, color = muted
                    )
                }

                Text(text = "Reasons:", style = label, fontWeight = FontWeight.Bold)
                if (result.reasons.isEmpty()) {
                    Text(text = "• No risk reasons triggered", style = small, fontSize = 11.sp, color = Color(0xFF2E7D32))
                } else {
                    result.reasons.forEach { r ->
                        Text(
                            text = "• [${r.tier}] ${r.code}: ${r.text}",
                            style = small, fontSize = 11.sp,
                            color = if (r.tier == "C") Color(0xFFEF6C00) else Color(0xFFC62828)
                        )
                    }
                }
                Text(text = "Decision ${result.decisionId} · server ${result.serverMs} ms", style = label, color = muted)
            }
        }
    }
}
