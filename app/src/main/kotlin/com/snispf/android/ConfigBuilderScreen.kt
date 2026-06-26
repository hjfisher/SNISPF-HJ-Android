package com.snispf.android

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.json.JSONArray
import org.json.JSONObject

// ── Data model ────────────────────────────────────────────────────────────────
data class BuilderState(
    // Mode
    val singleMode: Boolean = false,
    // Single
    val singleIp: String = "",
    val singleSni: String = "",
    // Pool - IPs & SNIs
    val connectIps: List<String> = listOf("172.66.41.252", "108.162.196.145"),
    val fakeSnis: List<String> = listOf("github.com", "google.com"),
    // Pool settings
    val activeSlots: Int = 3,
    val healthInterval: Int = 30,
    val healthTimeout: Int = 3,
    val probeCount: Int = 5,
    val lossThreshold: Float = 0.20f,
    val deadThreshold: Float = 0.80f,
    val drainTimeout: Int = 30,
    val maxDraining: Int = 5,
    val evictEvery: Int = 3,
    val evictCount: Int = 2,
    val recycleEnabled: Boolean = true,
    val recycleEvery: Int = 6,
    val recycleBatch: Int = 2,
    val recycleMinCooldown: Int = 180,
    val recycleMaxQuarantine: Int = 100,
    val quarantineScope: String = "both",
    // SNI axis (symmetric to IP axis above)
    val sniEvictEvery: Int = 3,
    val sniEvictCount: Int = 2,
    val sniRecycleEnabled: Boolean = true,
    val sniRecycleEvery: Int = 6,
    val sniRecycleBatch: Int = 2,
    val sniRecycleMinCooldown: Int = 180,
    val sniRecycleMaxQuarantine: Int = 100,
    val sniQuarantineScope: String = "both",
    val fakeSniFragmentReal: Boolean = true,
    // Bypass
    val bypassMethod: String = "combined",
    val fragmentStrategy: String = "sni_split",
    val fragmentDelay: Float = 0.10f,
    val fakeSniMethod: String = "prefix_fake",
    // IP Discovery
    val dynamicDiscovery: Boolean = false,
    val discoveryBatch: Int = 100,
    val discoveryInterval: Int = 120,
    val discoveryProbeTries: Int = 3,
    val discoveryTimeout: Float = 2.0f,
    val discoveryMinSuccess: Float = 0.50f,
    val discoveryMaxIps: Int = 200,
    // SNI Discovery (mirrors IP discovery on the SNI axis)
    val sniDynamicDiscovery: Boolean = false,
    val sniDiscoveryBatch: Int = 50,
    val sniDiscoveryInterval: Int = 120,
    val sniSourceRefreshInterval: Int = 21600,
    val sniDiscoveryProbeTries: Int = 3,
    val sniDiscoveryTimeout: Float = 2.0f,
    val sniDiscoveryMinSuccess: Float = 0.50f,
    val maxDynamicSnis: Int = 100,
    // Traffic Shaping (defeats flow-based DPI fingerprinting post-handshake)
    val shapingEnabled: Boolean = false,
    val shapingMinChunk: Int = 200,
    val shapingMaxChunk: Int = 1200,
    val shapingMinDelayMs: Int = 5,
    val shapingMaxDelayMs: Int = 40,
    val shapingDirection: String = "download_only",
    // Network
    val listenHost: String = "0.0.0.0",
    val listenPort: Int = 40443,
    val connectPort: Int = 443,
)

fun BuilderState.toJson(): String {
    val obj = JSONObject()
    obj.put("LISTEN_HOST",  listenHost)
    obj.put("LISTEN_PORT",  listenPort)
    obj.put("CONNECT_PORT", connectPort)
    obj.put("BYPASS_METHOD",     bypassMethod)
    obj.put("FRAGMENT_STRATEGY", fragmentStrategy)
    obj.put("FRAGMENT_DELAY",    String.format("%.2f", fragmentDelay).toDouble())
    obj.put("FAKE_SNI_METHOD",   fakeSniMethod)
    obj.put("FAKE_SNI_FRAGMENT_REAL", fakeSniFragmentReal)

    if (singleMode) {
        if (singleIp.isNotBlank())  obj.put("CONNECT_IP", singleIp.trim())
        if (singleSni.isNotBlank()) obj.put("FAKE_SNI",   singleSni.trim())
    } else {
        obj.put("ACTIVE_SLOTS",          activeSlots)
        obj.put("HEALTH_CHECK_INTERVAL", healthInterval)
        obj.put("HEALTH_CHECK_TIMEOUT",  healthTimeout)
        obj.put("PROBE_COUNT",           probeCount)
        obj.put("LOSS_THRESHOLD",        String.format("%.2f", lossThreshold).toDouble())
        obj.put("DEAD_THRESHOLD",        String.format("%.2f", deadThreshold).toDouble())
        obj.put("DRAIN_TIMEOUT",         drainTimeout)
        obj.put("MAX_DRAINING",          maxDraining)
        obj.put("EVICT_EVERY",           evictEvery)
        obj.put("EVICT_COUNT",           evictCount)
        obj.put("RECYCLE_ENABLED",       recycleEnabled)
        obj.put("RECYCLE_EVERY",         recycleEvery)
        obj.put("RECYCLE_BATCH",         recycleBatch)
        obj.put("RECYCLE_MIN_COOLDOWN",  recycleMinCooldown)
        obj.put("RECYCLE_MAX_QUARANTINE", recycleMaxQuarantine)
        obj.put("QUARANTINE_SCOPE",      quarantineScope)
        obj.put("SNI_EVICT_EVERY",            sniEvictEvery)
        obj.put("SNI_EVICT_COUNT",            sniEvictCount)
        obj.put("SNI_RECYCLE_ENABLED",        sniRecycleEnabled)
        obj.put("SNI_RECYCLE_EVERY",          sniRecycleEvery)
        obj.put("SNI_RECYCLE_BATCH",          sniRecycleBatch)
        obj.put("SNI_RECYCLE_MIN_COOLDOWN",   sniRecycleMinCooldown)
        obj.put("SNI_RECYCLE_MAX_QUARANTINE", sniRecycleMaxQuarantine)
        obj.put("SNI_QUARANTINE_SCOPE",       sniQuarantineScope)
        obj.put("DYNAMIC_IP_DISCOVERY",  dynamicDiscovery)
        if (dynamicDiscovery) {
            obj.put("DISCOVERY_BATCH",        discoveryBatch)
            obj.put("DISCOVERY_INTERVAL",     discoveryInterval)
            obj.put("DISCOVERY_PROBE_TRIES",  discoveryProbeTries)
            obj.put("DISCOVERY_TIMEOUT",      String.format("%.1f", discoveryTimeout).toDouble())
            obj.put("DISCOVERY_MIN_SUCCESS",  String.format("%.2f", discoveryMinSuccess).toDouble())
            obj.put("DISCOVERY_MAX_IPS",      discoveryMaxIps)
        }
        obj.put("DYNAMIC_SNI_DISCOVERY", sniDynamicDiscovery)
        if (sniDynamicDiscovery) {
            obj.put("SNI_DISCOVERY_BATCH",            sniDiscoveryBatch)
            obj.put("SNI_DISCOVERY_INTERVAL",         sniDiscoveryInterval)
            obj.put("SNI_SOURCE_REFRESH_INTERVAL",    sniSourceRefreshInterval)
            obj.put("SNI_DISCOVERY_PROBE_TRIES",      sniDiscoveryProbeTries)
            obj.put("SNI_DISCOVERY_TIMEOUT",          String.format("%.1f", sniDiscoveryTimeout).toDouble())
            obj.put("SNI_DISCOVERY_MIN_SUCCESS",      String.format("%.2f", sniDiscoveryMinSuccess).toDouble())
            obj.put("MAX_DYNAMIC_SNIS",               maxDynamicSnis)
        }
        obj.put("TRAFFIC_SHAPING_ENABLED", shapingEnabled)
        if (shapingEnabled) {
            obj.put("SHAPING_MIN_CHUNK",     shapingMinChunk)
            obj.put("SHAPING_MAX_CHUNK",     shapingMaxChunk)
            obj.put("SHAPING_MIN_DELAY_MS",  shapingMinDelayMs.toDouble())
            obj.put("SHAPING_MAX_DELAY_MS",  shapingMaxDelayMs.toDouble())
            obj.put("SHAPING_DIRECTION",     shapingDirection)
        }
        val ipsArr = JSONArray(); connectIps.forEach { ipsArr.put(it) }
        val snisArr = JSONArray(); fakeSnis.forEach { snisArr.put(it) }
        obj.put("CONNECT_IPS", ipsArr)
        obj.put("FAKE_SNIS",   snisArr)
    }
    return obj.toString(2)
}

fun builderFromJson(json: String): BuilderState {
    return try {
        val o = JSONObject(json)
        val singleMode = !o.has("CONNECT_IPS")
        val ips  = mutableListOf<String>()
        val snis = mutableListOf<String>()
        if (o.has("CONNECT_IPS")) { val a = o.getJSONArray("CONNECT_IPS"); repeat(a.length()) { ips.add(a.getString(it)) } }
        if (o.has("FAKE_SNIS"))   { val a = o.getJSONArray("FAKE_SNIS");   repeat(a.length()) { snis.add(a.getString(it)) } }
        BuilderState(
            singleMode       = singleMode,
            singleIp         = o.optString("CONNECT_IP", ""),
            singleSni        = o.optString("FAKE_SNI", ""),
            connectIps       = if (ips.isEmpty()) listOf("172.66.41.252") else ips,
            fakeSnis         = if (snis.isEmpty()) listOf("github.com") else snis,
            activeSlots      = o.optInt("ACTIVE_SLOTS", 3),
            healthInterval   = o.optInt("HEALTH_CHECK_INTERVAL", 30),
            healthTimeout    = o.optInt("HEALTH_CHECK_TIMEOUT", 3),
            probeCount       = o.optInt("PROBE_COUNT", 5),
            lossThreshold    = o.optDouble("LOSS_THRESHOLD", 0.20).toFloat(),
            deadThreshold    = o.optDouble("DEAD_THRESHOLD", 0.80).toFloat(),
            drainTimeout     = o.optInt("DRAIN_TIMEOUT", 30),
            maxDraining      = o.optInt("MAX_DRAINING", 5),
            evictEvery       = o.optInt("EVICT_EVERY", 3),
            evictCount       = o.optInt("EVICT_COUNT", 2),
            recycleEnabled       = o.optBoolean("RECYCLE_ENABLED", true),
            recycleEvery         = o.optInt("RECYCLE_EVERY", 6),
            recycleBatch         = o.optInt("RECYCLE_BATCH", 2),
            recycleMinCooldown   = o.optInt("RECYCLE_MIN_COOLDOWN", 180),
            recycleMaxQuarantine = o.optInt("RECYCLE_MAX_QUARANTINE", 100),
            quarantineScope      = o.optString("QUARANTINE_SCOPE", "both"),
            sniEvictEvery         = o.optInt("SNI_EVICT_EVERY", 3),
            sniEvictCount         = o.optInt("SNI_EVICT_COUNT", 2),
            sniRecycleEnabled     = o.optBoolean("SNI_RECYCLE_ENABLED", true),
            sniRecycleEvery       = o.optInt("SNI_RECYCLE_EVERY", 6),
            sniRecycleBatch       = o.optInt("SNI_RECYCLE_BATCH", 2),
            sniRecycleMinCooldown = o.optInt("SNI_RECYCLE_MIN_COOLDOWN", 180),
            sniRecycleMaxQuarantine = o.optInt("SNI_RECYCLE_MAX_QUARANTINE", 100),
            sniQuarantineScope    = o.optString("SNI_QUARANTINE_SCOPE", "both"),
            fakeSniFragmentReal   = o.optBoolean("FAKE_SNI_FRAGMENT_REAL", true),
            bypassMethod     = o.optString("BYPASS_METHOD", "combined"),
            fragmentStrategy = o.optString("FRAGMENT_STRATEGY", "sni_split"),
            fragmentDelay    = o.optDouble("FRAGMENT_DELAY", 0.10).toFloat(),
            fakeSniMethod    = o.optString("FAKE_SNI_METHOD", "prefix_fake"),
            dynamicDiscovery    = o.optBoolean("DYNAMIC_IP_DISCOVERY", false),
            discoveryBatch      = o.optInt("DISCOVERY_BATCH", 100),
            discoveryInterval   = o.optInt("DISCOVERY_INTERVAL", 120),
            discoveryProbeTries = o.optInt("DISCOVERY_PROBE_TRIES", 3),
            discoveryTimeout    = o.optDouble("DISCOVERY_TIMEOUT", 2.0).toFloat(),
            discoveryMinSuccess = o.optDouble("DISCOVERY_MIN_SUCCESS", 0.50).toFloat(),
            discoveryMaxIps     = o.optInt("DISCOVERY_MAX_IPS", 200),
            sniDynamicDiscovery      = o.optBoolean("DYNAMIC_SNI_DISCOVERY", false),
            sniDiscoveryBatch        = o.optInt("SNI_DISCOVERY_BATCH", 50),
            sniDiscoveryInterval     = o.optInt("SNI_DISCOVERY_INTERVAL", 120),
            sniSourceRefreshInterval = o.optInt("SNI_SOURCE_REFRESH_INTERVAL", 21600),
            sniDiscoveryProbeTries   = o.optInt("SNI_DISCOVERY_PROBE_TRIES", 3),
            sniDiscoveryTimeout      = o.optDouble("SNI_DISCOVERY_TIMEOUT", 2.0).toFloat(),
            sniDiscoveryMinSuccess   = o.optDouble("SNI_DISCOVERY_MIN_SUCCESS", 0.50).toFloat(),
            maxDynamicSnis           = o.optInt("MAX_DYNAMIC_SNIS", 100),
            shapingEnabled    = o.optBoolean("TRAFFIC_SHAPING_ENABLED", false),
            shapingMinChunk   = o.optInt("SHAPING_MIN_CHUNK", 200),
            shapingMaxChunk   = o.optInt("SHAPING_MAX_CHUNK", 1200),
            shapingMinDelayMs = o.optDouble("SHAPING_MIN_DELAY_MS", 5.0).toInt(),
            shapingMaxDelayMs = o.optDouble("SHAPING_MAX_DELAY_MS", 40.0).toInt(),
            shapingDirection  = o.optString("SHAPING_DIRECTION", "download_only"),
            listenHost       = o.optString("LISTEN_HOST", "0.0.0.0"),
            listenPort       = o.optInt("LISTEN_PORT", 40443),
            connectPort      = o.optInt("CONNECT_PORT", 443),
        )
    } catch (_: Exception) { BuilderState() }
}

// ── Main screen ───────────────────────────────────────────────────────────────
@Composable
fun ConfigBuilderTab(vm: SnispfViewModel) {
    val currentJson = vm.uiState.collectAsState().value.configJson
    var bs by remember { mutableStateOf(builderFromJson(currentJson)) }
    var saved by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        // Save button bar
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface)
                .padding(horizontal = 16.dp, vertical = 8.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Config Builder", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                if (saved) Text("✓ Saved", color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
                Button(
                    onClick = { vm.saveConfig(bs.toJson()); saved = true },
                    modifier = Modifier.height(36.dp),
                    contentPadding = PaddingValues(horizontal = 16.dp)
                ) {
                    Icon(Icons.Default.Save, null, modifier = Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Save & Apply")
                }
            }
        }

        HorizontalDivider()

        LazyColumn(
            modifier = Modifier.fillMaxSize(),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // ── Mode ──────────────────────────────────────────────────────────
            item {
                BSection("Mode", Icons.Default.Tune) {
                    BToggleRow(
                        label    = "Single-Pair mode (Legacy)",
                        sublabel = "Disable pool — use one IP + SNI directly",
                        checked  = bs.singleMode,
                        onChange = { bs = bs.copy(singleMode = it); saved = false }
                    )
                }
            }

            // ── Single fields ─────────────────────────────────────────────────
            if (bs.singleMode) {
                item {
                    BSection("Single Target", Icons.Default.Link) {
                        BTextField("Connect IP", bs.singleIp, "172.66.41.252", KeyboardType.Ascii) {
                            bs = bs.copy(singleIp = it); saved = false
                        }
                        BTextField("Fake SNI", bs.singleSni, "cdnjs.cloudflare.com", KeyboardType.Ascii) {
                            bs = bs.copy(singleSni = it); saved = false
                        }
                    }
                }
            }

            // ── Pool: IPs & SNIs ──────────────────────────────────────────────
            if (!bs.singleMode) {
                item {
                    BSection("IP List  (${bs.connectIps.size} IPs)", Icons.Default.Dns) {
                        BListEditor(
                            items       = bs.connectIps,
                            placeholder = "e.g. 172.66.41.252",
                            keyboardType = KeyboardType.Ascii,
                            onChange    = { bs = bs.copy(connectIps = it); saved = false }
                        )
                    }
                }

                item {
                    BSection("SNI List  (${bs.fakeSnis.size} SNIs)", Icons.Default.Tag) {
                        BListEditor(
                            items       = bs.fakeSnis,
                            placeholder = "e.g. github.com",
                            keyboardType = KeyboardType.Ascii,
                            onChange    = { bs = bs.copy(fakeSnis = it); saved = false }
                        )
                    }
                }

                // ── Pool settings ─────────────────────────────────────────────
                item {
                    BSection("Pool Settings", Icons.Default.Hub) {
                        BSliderRow("Active Slots", bs.activeSlots, 1, 20, "{v} slots") {
                            bs = bs.copy(activeSlots = it); saved = false
                        }
                        BNumberRow("Health Check Interval (s)", bs.healthInterval, 5, 300) {
                            bs = bs.copy(healthInterval = it); saved = false
                        }
                        BNumberRow("Health Check Timeout (s)", bs.healthTimeout, 1, 30) {
                            bs = bs.copy(healthTimeout = it); saved = false
                        }
                        BNumberRow("Probe Count", bs.probeCount, 1, 20) {
                            bs = bs.copy(probeCount = it); saved = false
                        }
                        BSliderRow("Loss Threshold", (bs.lossThreshold * 100).toInt(), 0, 100, "{v}%") {
                            bs = bs.copy(lossThreshold = it / 100f); saved = false
                        }
                        BSliderRow("Dead Threshold", (bs.deadThreshold * 100).toInt(), 0, 100, "{v}%") {
                            bs = bs.copy(deadThreshold = it / 100f); saved = false
                        }
                        BNumberRow("Drain Timeout (s)", bs.drainTimeout, 5, 300) {
                            bs = bs.copy(drainTimeout = it); saved = false
                        }
                        BNumberRow("Max Draining", bs.maxDraining, 1, 50) {
                            bs = bs.copy(maxDraining = it); saved = false
                        }
                        BNumberRow("Evict Every (cycles)", bs.evictEvery, 1, 20) {
                            bs = bs.copy(evictEvery = it); saved = false
                        }
                        BNumberRow("Evict Count", bs.evictCount, 1, 20) {
                            bs = bs.copy(evictCount = it); saved = false
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        BToggleRow("Recycling", "Re-test evicted IPs and bring back the healthy ones", bs.recycleEnabled) {
                            bs = bs.copy(recycleEnabled = it); saved = false
                        }
                        if (bs.recycleEnabled) {
                            BNumberRow("Recycle Every (cycles)", bs.recycleEvery, 1, 50) {
                                bs = bs.copy(recycleEvery = it); saved = false
                            }
                            BNumberRow("Recycle Batch", bs.recycleBatch, 1, 20) {
                                bs = bs.copy(recycleBatch = it); saved = false
                            }
                            BNumberRow("Min Cooldown (s)", bs.recycleMinCooldown, 10, 3600) {
                                bs = bs.copy(recycleMinCooldown = it); saved = false
                            }
                            BNumberRow("Max Quarantine Size", bs.recycleMaxQuarantine, 10, 1000) {
                                bs = bs.copy(recycleMaxQuarantine = it); saved = false
                            }
                        }
                        BDropdown(
                            label = "Quarantine Scope",
                            value = bs.quarantineScope,
                            options = listOf(
                                "both"    to "both — static + dynamic IPs",
                                "static"  to "static — CONNECT_IPS only",
                                "dynamic" to "dynamic — discovered IPs only",
                            ),
                            onChange = { bs = bs.copy(quarantineScope = it); saved = false }
                        )
                    }
                }

                item {
                    BSection("SNI Pool Settings  (symmetric to IP axis)", Icons.Default.Tag) {
                        BNumberRow("SNI Evict Every (cycles)", bs.sniEvictEvery, 1, 20) {
                            bs = bs.copy(sniEvictEvery = it); saved = false
                        }
                        BNumberRow("SNI Evict Count", bs.sniEvictCount, 1, 20) {
                            bs = bs.copy(sniEvictCount = it); saved = false
                        }
                        HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                        BToggleRow("SNI Recycling", "Re-test evicted SNIs and bring back healthy ones", bs.sniRecycleEnabled) {
                            bs = bs.copy(sniRecycleEnabled = it); saved = false
                        }
                        if (bs.sniRecycleEnabled) {
                            BNumberRow("SNI Recycle Every (cycles)", bs.sniRecycleEvery, 1, 50) {
                                bs = bs.copy(sniRecycleEvery = it); saved = false
                            }
                            BNumberRow("SNI Recycle Batch", bs.sniRecycleBatch, 1, 20) {
                                bs = bs.copy(sniRecycleBatch = it); saved = false
                            }
                            BNumberRow("SNI Min Cooldown (s)", bs.sniRecycleMinCooldown, 10, 3600) {
                                bs = bs.copy(sniRecycleMinCooldown = it); saved = false
                            }
                            BNumberRow("SNI Max Quarantine Size", bs.sniRecycleMaxQuarantine, 10, 1000) {
                                bs = bs.copy(sniRecycleMaxQuarantine = it); saved = false
                            }
                        }
                        BDropdown(
                            label = "SNI Quarantine Scope",
                            value = bs.sniQuarantineScope,
                            options = listOf(
                                "both"    to "both — static + dynamic SNIs",
                                "static"  to "static — FAKE_SNIS only",
                                "dynamic" to "dynamic — discovered SNIs only",
                            ),
                            onChange = { bs = bs.copy(sniQuarantineScope = it); saved = false }
                        )
                    }
                }

                // ── IP Discovery ──────────────────────────────────────────────
                item {
                    BSection("IP Discovery", Icons.Default.TravelExplore) {
                        BToggleRow(
                            label    = "Dynamic IP Discovery",
                            sublabel = "Scan Cloudflare CIDRs at runtime to find new IPs",
                            checked  = bs.dynamicDiscovery,
                            onChange = { bs = bs.copy(dynamicDiscovery = it); saved = false }
                        )
                        if (bs.dynamicDiscovery) {
                            BNumberRow("Batch Size", bs.discoveryBatch, 10, 500) {
                                bs = bs.copy(discoveryBatch = it); saved = false
                            }
                            BNumberRow("Scan Interval (s)", bs.discoveryInterval, 30, 3600) {
                                bs = bs.copy(discoveryInterval = it); saved = false
                            }
                            BNumberRow("Probe Tries per IP", bs.discoveryProbeTries, 1, 10) {
                                bs = bs.copy(discoveryProbeTries = it); saved = false
                            }
                            BNumberRow("Probe Timeout (s)", bs.discoveryTimeout.toInt(), 1, 10) {
                                bs = bs.copy(discoveryTimeout = it.toFloat()); saved = false
                            }
                            BSliderRow("Min Success Rate", (bs.discoveryMinSuccess * 100).toInt(), 0, 100, "{v}%") {
                                bs = bs.copy(discoveryMinSuccess = it / 100f); saved = false
                            }
                            BSliderRow("Max IPs to collect", bs.discoveryMaxIps, 10, 500, "{v} IPs") {
                                bs = bs.copy(discoveryMaxIps = it); saved = false
                            }
                        }
                    }
                }

                // ── SNI Discovery (mirrors IP Discovery) ────────────────────────
                item {
                    BSection("SNI Discovery", Icons.Default.TravelExplore) {
                        BToggleRow(
                            label    = "Dynamic SNI Discovery",
                            sublabel = "Sample Tranco/Umbrella/Majestic domain lists to find new Cloudflare-hosted SNIs",
                            checked  = bs.sniDynamicDiscovery,
                            onChange = { bs = bs.copy(sniDynamicDiscovery = it); saved = false }
                        )
                        if (bs.sniDynamicDiscovery) {
                            BNumberRow("Batch Size", bs.sniDiscoveryBatch, 10, 500) {
                                bs = bs.copy(sniDiscoveryBatch = it); saved = false
                            }
                            BNumberRow("Scan Interval (s)", bs.sniDiscoveryInterval, 30, 3600) {
                                bs = bs.copy(sniDiscoveryInterval = it); saved = false
                            }
                            BNumberRow("Source Refresh (s)", bs.sniSourceRefreshInterval, 300, 86400) {
                                bs = bs.copy(sniSourceRefreshInterval = it); saved = false
                            }
                            BNumberRow("Probe Tries per SNI", bs.sniDiscoveryProbeTries, 1, 10) {
                                bs = bs.copy(sniDiscoveryProbeTries = it); saved = false
                            }
                            BNumberRow("Probe Timeout (s)", bs.sniDiscoveryTimeout.toInt(), 1, 10) {
                                bs = bs.copy(sniDiscoveryTimeout = it.toFloat()); saved = false
                            }
                            BSliderRow("Min Success Rate", (bs.sniDiscoveryMinSuccess * 100).toInt(), 0, 100, "{v}%") {
                                bs = bs.copy(sniDiscoveryMinSuccess = it / 100f); saved = false
                            }
                            BSliderRow("Max Dynamic SNIs", bs.maxDynamicSnis, 10, 500, "{v} SNIs") {
                                bs = bs.copy(maxDynamicSnis = it); saved = false
                            }
                        }
                    }
                }
            }

            // ── Bypass ────────────────────────────────────────────────────────
            item {
                BSection("Bypass Method", Icons.Default.Shield) {
                    BDropdown(
                        label   = "Method",
                        value   = bs.bypassMethod,
                        options = listOf(
                            "fragment"  to "Fragment — TLS fragmentation",
                            "fake_sni"  to "Fake SNI — SNI substitution",
                            "combined"  to "Combined — Fragment + Fake SNI",
                        ),
                        onChange = { bs = bs.copy(bypassMethod = it); saved = false }
                    )
                    BDropdown(
                        label   = "Fragment Strategy",
                        value   = bs.fragmentStrategy,
                        options = listOf(
                            "sni_split"       to "sni_split — Split at SNI (default)",
                            "half"            to "half — Two equal halves",
                            "multi"           to "multi — Small 5-10 byte chunks",
                            "tls_record_frag" to "tls_record_frag — TLS Record layer split",
                        ),
                        onChange = { bs = bs.copy(fragmentStrategy = it); saved = false }
                    )
                    BSliderRow(
                        "Fragment Delay", (bs.fragmentDelay * 100).toInt(), 0, 100,
                        "${String.format("%.2f", bs.fragmentDelay)}s"
                    ) {
                        bs = bs.copy(fragmentDelay = it / 100f); saved = false
                    }
                    BDropdown(
                        label   = "Fake SNI Method",
                        value   = bs.fakeSniMethod,
                        options = listOf(
                            "prefix_fake"  to "prefix_fake (default)",
                            "postfix_fake" to "postfix_fake",
                            "custom"       to "custom",
                        ),
                        onChange = { bs = bs.copy(fakeSniMethod = it); saved = false }
                    )
                    BToggleRow("Fragment Real ClientHello", "Also fragment the real handshake (not just the fake SNI)", bs.fakeSniFragmentReal) {
                        bs = bs.copy(fakeSniFragmentReal = it); saved = false
                    }
                }
            }

            // ── Traffic Shaping ───────────────────────────────────────────────
            item {
                BSection("Traffic Shaping", Icons.Default.GraphicEq) {
                    BToggleRow(
                        label    = "Traffic Shaping",
                        sublabel = "Reshapes post-handshake relay traffic so it doesn't look like a flat proxy tunnel — defeats flow-based DPI",
                        checked  = bs.shapingEnabled,
                        onChange = { bs = bs.copy(shapingEnabled = it); saved = false }
                    )
                    if (bs.shapingEnabled) {
                        BDropdown(
                            label = "Direction",
                            value = bs.shapingDirection,
                            options = listOf(
                                "download_only" to "download_only — shape server→client only (default)",
                                "both"          to "both — shape both directions",
                            ),
                            onChange = { bs = bs.copy(shapingDirection = it); saved = false }
                        )
                        BNumberRow("Min Chunk (bytes)", bs.shapingMinChunk, 1, 8192) {
                            bs = bs.copy(shapingMinChunk = it); saved = false
                        }
                        BNumberRow("Max Chunk (bytes)", bs.shapingMaxChunk, bs.shapingMinChunk, 16384) {
                            bs = bs.copy(shapingMaxChunk = it); saved = false
                        }
                        BNumberRow("Min Delay (ms)", bs.shapingMinDelayMs, 0, 1000) {
                            bs = bs.copy(shapingMinDelayMs = it); saved = false
                        }
                        BNumberRow("Max Delay (ms)", bs.shapingMaxDelayMs, bs.shapingMinDelayMs, 2000) {
                            bs = bs.copy(shapingMaxDelayMs = it); saved = false
                        }
                        Text(
                            "Adds latency — only enable on networks known to fingerprint flow patterns, not just the handshake.",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            lineHeight = 16.sp,
                        )
                    }
                }
            }

            // ── Network ───────────────────────────────────────────────────────
            item {
                BSection("Network", Icons.Default.Wifi) {
                    BTextField("Listen Host", bs.listenHost, "0.0.0.0", KeyboardType.Ascii) {
                        bs = bs.copy(listenHost = it); saved = false
                    }
                    BNumberRow("Listen Port", bs.listenPort, 1024, 65535) {
                        bs = bs.copy(listenPort = it); saved = false
                    }
                    BNumberRow("Connect Port", bs.connectPort, 1, 65535) {
                        bs = bs.copy(connectPort = it); saved = false
                    }
                }
                Spacer(Modifier.height(8.dp))
            }
        }
    }
}

// ── Reusable components ───────────────────────────────────────────────────────

@Composable
fun BSection(title: String, icon: ImageVector, content: @Composable ColumnScope.() -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape    = RoundedCornerShape(12.dp),
        colors   = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
    ) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Icon(icon, null, modifier = Modifier.size(18.dp), tint = MaterialTheme.colorScheme.primary)
                Text(title, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
            }
            HorizontalDivider(color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
            content()
        }
    }
}

@Composable
fun BToggleRow(label: String, sublabel: String = "", checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(label, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
            if (sublabel.isNotBlank())
                Text(sublabel, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Switch(checked = checked, onCheckedChange = onChange)
    }
}

@Composable
fun BTextField(label: String, value: String, placeholder: String, keyboardType: KeyboardType, onChange: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        OutlinedTextField(
            value         = value,
            onValueChange = onChange,
            placeholder   = { Text(placeholder, style = MaterialTheme.typography.bodySmall) },
            modifier      = Modifier.fillMaxWidth(),
            singleLine    = true,
            keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
            shape         = RoundedCornerShape(8.dp),
        )
    }
}

@Composable
fun BNumberRow(label: String, value: Int, min: Int, max: Int, onChange: (Int) -> Unit) {
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        Text(label, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(4.dp)) {
            IconButton(
                onClick  = { if (value > min) onChange(value - 1) },
                modifier = Modifier.size(32.dp)
            ) { Icon(Icons.Default.Remove, null, modifier = Modifier.size(16.dp)) }
            Text(
                "$value",
                modifier  = Modifier
                    .widthIn(min = 40.dp)
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(6.dp))
                    .padding(horizontal = 8.dp, vertical = 4.dp),
                fontWeight = FontWeight.Bold,
                style = MaterialTheme.typography.bodyMedium,
            )
            IconButton(
                onClick  = { if (value < max) onChange(value + 1) },
                modifier = Modifier.size(32.dp)
            ) { Icon(Icons.Default.Add, null, modifier = Modifier.size(16.dp)) }
        }
    }
}

@Composable
fun BSliderRow(label: String, value: Int, min: Int, max: Int, display: String, onChange: (Int) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(2.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, style = MaterialTheme.typography.bodyMedium)
            Text(
                display.replace("{v}", "$value"),
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }
        Slider(
            value         = value.toFloat(),
            onValueChange = { onChange(it.toInt()) },
            valueRange    = min.toFloat()..max.toFloat(),
            modifier      = Modifier.fillMaxWidth(),
        )
    }
}

@Composable
fun BDropdown(label: String, value: String, options: List<Pair<String, String>>, onChange: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    val current = options.firstOrNull { it.first == value }?.second ?: value

    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Box {
            OutlinedButton(
                onClick  = { expanded = true },
                modifier = Modifier.fillMaxWidth(),
                shape    = RoundedCornerShape(8.dp),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp)
            ) {
                Text(current, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall)
                Icon(Icons.Default.ArrowDropDown, null, modifier = Modifier.size(20.dp))
            }
            DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
                options.forEach { (key, desc) ->
                    DropdownMenuItem(
                        text    = { Text(desc, style = MaterialTheme.typography.bodySmall) },
                        onClick = { onChange(key); expanded = false },
                        leadingIcon = if (key == value) ({ Icon(Icons.Default.Check, null, tint = MaterialTheme.colorScheme.primary) }) else null
                    )
                }
            }
        }
    }
}

@Composable
fun BListEditor(items: List<String>, placeholder: String, keyboardType: KeyboardType, onChange: (List<String>) -> Unit) {
    var newItem by remember { mutableStateOf("") }

    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        // Existing items
        items.forEachIndexed { idx, item ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(item, Modifier.weight(1f), style = MaterialTheme.typography.bodySmall,
                    fontWeight = FontWeight.Medium)
                IconButton(
                    onClick  = { onChange(items.toMutableList().also { it.removeAt(idx) }) },
                    modifier = Modifier.size(28.dp)
                ) { Icon(Icons.Default.Close, null, modifier = Modifier.size(14.dp), tint = Color(0xFFF44336)) }
            }
        }

        // Add new item row
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value         = newItem,
                onValueChange = { newItem = it },
                placeholder   = { Text(placeholder, style = MaterialTheme.typography.bodySmall) },
                modifier      = Modifier.weight(1f),
                singleLine    = true,
                keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
                shape         = RoundedCornerShape(8.dp),
            )
            IconButton(
                onClick = {
                    val trimmed = newItem.trim()
                    if (trimmed.isNotBlank() && !items.contains(trimmed)) {
                        onChange(items + trimmed)
                        newItem = ""
                    }
                },
                modifier = Modifier
                    .size(48.dp)
                    .background(MaterialTheme.colorScheme.primary, RoundedCornerShape(8.dp))
            ) {
                Icon(Icons.Default.Add, null, tint = Color.Black)
            }
        }
    }
}
