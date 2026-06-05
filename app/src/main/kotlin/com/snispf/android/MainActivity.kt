package com.snispf.android

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.chaquo.python.android.AndroidPlatform
import com.chaquo.python.Python

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        setContent { SnispfTheme { Surface(Modifier.fillMaxSize()) { SnispfApp() } } }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SnispfApp(vm: SnispfViewModel = viewModel()) {
    val state by vm.uiState.collectAsState()
    var tab by remember { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("SNISPF-HJ", fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.primary) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.surface)
            )
        },
        bottomBar = {
            NavigationBar {
                listOf(
                    Triple(0, Icons.Default.Home,     "Proxy"),
                    Triple(1, Icons.Default.BarChart, "Stats"),
                    Triple(2, Icons.Default.Settings, "Config"),
                    Triple(3, Icons.Default.List,     "Log"),
                ).forEach { (idx, icon, label) ->
                    NavigationBarItem(
                        selected = tab == idx,
                        onClick  = { tab = idx },
                        icon     = { Icon(icon, null) },
                        label    = { Text(label) }
                    )
                }
            }
        }
    ) { padding ->
        Box(Modifier.padding(padding)) {
            when (tab) {
                0 -> ProxyTab(state, vm)
                1 -> StatsTab(state)
                2 -> ConfigTab(state, vm)
                3 -> LogTab(state, vm)
            }
        }
    }
}

// ── Tab 0: Proxy ──────────────────────────────────────────────────────────────
@Composable
fun ProxyTab(state: UiState, vm: SnispfViewModel) {
    val isRunning = state.status == ProxyStatus.RUNNING
    val isBusy    = state.status == ProxyStatus.STARTING || state.status == ProxyStatus.STOPPING

    val dotColor by animateColorAsState(
        targetValue = when (state.status) {
            ProxyStatus.RUNNING  -> Color(0xFF4CAF50)
            ProxyStatus.ERROR    -> Color(0xFFF44336)
            ProxyStatus.STARTING,
            ProxyStatus.STOPPING -> Color(0xFFFFC107)
            else                 -> Color(0xFF757575)
        }, animationSpec = tween(400), label = "dot"
    )

    Column(
        modifier = Modifier.fillMaxSize().padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(20.dp, Alignment.CenterVertically)
    ) {
        // Status circle
        Box(Modifier.size(130.dp).clip(CircleShape).background(dotColor.copy(alpha = 0.15f)), Alignment.Center) {
            Box(Modifier.size(88.dp).clip(CircleShape).background(dotColor), Alignment.Center) {
                if (isBusy)
                    CircularProgressIndicator(color = Color.White, strokeWidth = 3.dp)
                else
                    Icon(
                        if (isRunning) Icons.Default.CheckCircle else Icons.Default.Cancel,
                        contentDescription = null, tint = Color.White, modifier = Modifier.size(42.dp)
                    )
            }
        }

        Text(
            text = when (state.status) {
                ProxyStatus.RUNNING  -> "Running"
                ProxyStatus.STARTING -> "Starting..."
                ProxyStatus.STOPPING -> "Stopping..."
                ProxyStatus.ERROR    -> "Error"
                ProxyStatus.STOPPED  -> "Stopped"
            },
            style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold
        )

        if (isRunning) {
            // Proxy address
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.primaryContainer)) {
                Row(
                    modifier = Modifier.padding(horizontal = 20.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Icon(Icons.Default.Wifi, null, tint = MaterialTheme.colorScheme.primary)
                    Text(
                        "127.0.0.1:${state.listenPort}",
                        fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
            }
            // Quick stats
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                MiniCard("Active", "${state.pool.activeConnections}", Icons.Default.Link)
                MiniCard("Uptime", formatUptime(state.pool.uptimeSeconds), Icons.Default.Timer)
                MiniCard("Pool", "${state.pool.probedStable}/${state.pool.pairsProbed}", Icons.Default.Hub)
            }
        }

        // Error
        state.errorMessage?.let { err ->
            Card(colors = CardDefaults.cardColors(containerColor = Color(0xFF2C1010))) {
                Text(err, Modifier.padding(12.dp), color = Color(0xFFEF9A9A),
                    style = MaterialTheme.typography.bodySmall, fontFamily = FontFamily.Monospace)
            }
        }

        // Root toggle
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)
        ) {
            Row(
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(Icons.Default.Security, null, tint = MaterialTheme.colorScheme.secondary)
                Spacer(Modifier.width(12.dp))
                Column(Modifier.weight(1f)) {
                    Text("Root Mode", fontWeight = FontWeight.Medium)
                    Text("Enables wrong_seq and TTL trick", style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Switch(checked = state.useRoot, onCheckedChange = { vm.setUseRoot(it) }, enabled = !isRunning)
            }
        }

        // Start / Stop
        Button(
            onClick  = { if (isRunning || isBusy) vm.stop() else vm.start() },
            enabled  = !isBusy,
            modifier = Modifier.fillMaxWidth().height(56.dp),
            colors   = ButtonDefaults.buttonColors(
                containerColor = if (isRunning) Color(0xFFC62828) else MaterialTheme.colorScheme.primary
            )
        ) {
            Icon(if (isRunning) Icons.Default.Stop else Icons.Default.PlayArrow, null)
            Spacer(Modifier.width(8.dp))
            Text(if (isRunning) "Stop" else "Start", fontSize = 18.sp, fontWeight = FontWeight.Bold)
        }
    }
}

@Composable
fun MiniCard(label: String, value: String, icon: ImageVector) {
    Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
        Column(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, null, modifier = Modifier.size(16.dp), tint = MaterialTheme.colorScheme.secondary)
            Spacer(Modifier.height(2.dp))
            Text(value, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
            Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

fun formatUptime(s: Int): String = when {
    s >= 3600 -> "${s/3600}h${(s%3600)/60}m"
    s >= 60   -> "${s/60}m${s%60}s"
    else      -> "${s}s"
}

// ── Tab 1: Stats ──────────────────────────────────────────────────────────────
@Composable
fun StatsTab(state: UiState) {
    val p = state.pool
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {

        SectionTitle("Connections")
        StatsCard {
            StatRow("Active",  "${p.activeConnections}", Color(0xFF4CAF50))
            StatRow("Total",   "${p.totalConnections}")
            StatRow("Uptime",  formatUptime(p.uptimeSeconds))
        }

        SectionTitle("Active Pool  (${p.activeSlots} active slots)")
        StatsCard {
            StatRow("Stable pairs", "${p.probedStable}", Color(0xFF4CAF50))
            StatRow("Weak pairs",   "${p.probedWeak}",   Color(0xFFFFC107))
            StatRow("Dead pairs",   "${p.probedDead}",   Color(0xFFF44336))
            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
            StatRow("Probed total", "${p.probedTotal}")
        }

        SectionTitle("Probe Discovery  (${p.pairsProbed}/${p.pairsTotal})")
        val probeProgress = if (p.pairsTotal > 0) p.pairsProbed.toFloat() / p.pairsTotal else 0f
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                LinearProgressIndicator(
                    progress = { probeProgress },
                    modifier = Modifier.fillMaxWidth(),
                    color    = if (p.discoveryDone) Color(0xFF4CAF50) else MaterialTheme.colorScheme.primary,
                )
                StatRow("Probed",      "${p.pairsProbed}",   Color(0xFF4CAF50))
                StatRow("Unprobed",    "${p.pairsUnprobed}", Color(0xFFFFC107))
                StatRow("Total pairs", "${p.pairsTotal}", note = "(grows with IP discovery)")
                StatRow("Status",
                    if (p.discoveryDone) "Complete ✓" else "Exploring...",
                    if (p.discoveryDone) Color(0xFF4CAF50) else Color(0xFFFFC107)
                )
            }
        }

        SectionTitle("IP Discovery")
        Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                StatRow("Status",
                    if (p.dynamicDiscoveryEnabled) "Enabled" else "Disabled",
                    if (p.dynamicDiscoveryEnabled) Color(0xFF4CAF50) else Color(0xFF757575)
                )
                if (p.dynamicDiscoveryEnabled) {
                    StatRow("Dynamic IPs found", "${p.dynamicIpsFound}", Color(0xFF4CAF50))
                    StatRow("Total pairs now",   "${p.pairsTotal}")
                    Text(
                        "New Cloudflare IPs are injected every ~2 min. " +
                        "Total pairs = (static IPs + dynamic IPs) x SNIs",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 16.sp,
                    )
                } else {
                    Text(
                        "Set DYNAMIC_IP_DISCOVERY: true in config to enable automatic Cloudflare IP scanning.",
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        lineHeight = 16.sp,
                    )
                }
            }
        }

        if (state.status == ProxyStatus.STOPPED) {
            Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
                Text("Proxy is stopped — stats will appear after starting.",
                    Modifier.padding(16.dp), color = MaterialTheme.colorScheme.onSurfaceVariant,
                    style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}

@Composable
fun SectionTitle(text: String) =
    Text(text, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)

@Composable
fun StatsCard(content: @Composable ColumnScope.() -> Unit) {
    Card(modifier = Modifier.fillMaxWidth(), shape = RoundedCornerShape(12.dp)) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp), content = content)
    }
}

@Composable
fun StatRow(label: String, value: String, valueColor: Color = MaterialTheme.colorScheme.onSurface, note: String? = null) {
    Column {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(label, color = MaterialTheme.colorScheme.onSurfaceVariant, style = MaterialTheme.typography.bodyMedium)
            Text(value, color = valueColor, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
        }
        if (note != null) {
            Text(note, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

// ── Tab 2: Config ─────────────────────────────────────────────────────────────
@Composable
fun ConfigTab(state: UiState, vm: SnispfViewModel) {
    var text    by remember(state.configJson) { mutableStateOf(state.configJson) }
    var isValid by remember { mutableStateOf(true) }
    var saved   by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
        Text("Config JSON", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)

        Card(colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surfaceVariant)) {
            Text(
                "Build your config at hjfisher.github.io/SNISPF-HJ-Configurator then paste it here.",
                modifier = Modifier.padding(12.dp),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }

        Card(
            modifier = Modifier.fillMaxWidth().weight(1f),
            shape  = RoundedCornerShape(12.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isValid) Color(0xFF0F1A2E) else Color(0xFF2E0F0F)
            )
        ) {
            BasicTextField(
                value = text,
                onValueChange = {
                    text = it; saved = false
                    isValid = try { org.json.JSONObject(it); true } catch (_: Exception) { false }
                },
                modifier   = Modifier.fillMaxSize().padding(12.dp),
                textStyle  = TextStyle(fontFamily = FontFamily.Monospace, fontSize = 12.sp, color = Color(0xFFDDDDDD))
            )
        }

        Row(horizontalArrangement = Arrangement.spacedBy(4.dp), verticalAlignment = Alignment.CenterVertically) {
            if (!isValid) Text("Invalid JSON", color = Color(0xFFF44336), style = MaterialTheme.typography.bodySmall)
            if (saved)    Text("✓ Saved", color = Color(0xFF4CAF50), style = MaterialTheme.typography.bodySmall)
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedButton(
                onClick  = { text = DEFAULT_CONFIG; isValid = true; saved = false },
                modifier = Modifier.weight(1f)
            ) { Text("Reset") }

            Button(
                onClick  = { if (isValid) { vm.saveConfig(text); saved = true } },
                enabled  = isValid,
                modifier = Modifier.weight(1f)
            ) {
                Icon(Icons.Default.Save, null)
                Spacer(Modifier.width(4.dp))
                Text("Save")
            }
        }
    }
}

// ── Tab 3: Log ────────────────────────────────────────────────────────────────
@Composable
fun LogTab(state: UiState, vm: SnispfViewModel) {
    val listState = rememberLazyListState()
    LaunchedEffect(state.logs.size) {
        if (state.logs.isNotEmpty()) listState.animateScrollToItem(state.logs.size - 1)
    }

    Column(Modifier.fillMaxSize().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Log  (${state.logs.size} lines)", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
            IconButton(onClick = { vm.clearLogs() }) { Icon(Icons.Default.Delete, null) }
        }

        Card(
            modifier = Modifier.fillMaxSize(),
            shape    = RoundedCornerShape(12.dp),
            colors   = CardDefaults.cardColors(containerColor = Color(0xFF080808))
        ) {
            LazyColumn(
                state    = listState,
                modifier = Modifier.fillMaxSize().padding(10.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                if (state.logs.isEmpty()) {
                    item {
                        Text("No logs yet...", color = Color(0xFF444444),
                            fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    }
                } else {
                    items(items = state.logs) { line ->
                        Text(
                            text  = line,
                            color = when {
                                "ERROR" in line            -> Color(0xFFEF5350)
                                "warn"  in line.lowercase() -> Color(0xFFFFA726)
                                "weak"  in line             -> Color(0xFFFFA726)
                                "running" in line || "stable" in line || "active" in line -> Color(0xFF66BB6A)
                                "[Bridge]" in line || "Listening" in line -> Color(0xFF64B5F6)
                                else                       -> Color(0xFFBBBBBB)
                            },
                            fontFamily = FontFamily.Monospace,
                            fontSize   = 11.sp,
                            lineHeight = 16.sp,
                        )
                    }
                }
            }
        }
    }
}

// ── Theme ─────────────────────────────────────────────────────────────────────
@Composable
fun SnispfTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = darkColorScheme(
            primary        = Color(0xFF64B5F6),
            secondary      = Color(0xFF4DB6AC),
            background     = Color(0xFF0A0A0A),
            surface        = Color(0xFF141414),
            surfaceVariant = Color(0xFF1E1E1E),
            onPrimary      = Color.Black,
            onBackground   = Color.White,
            onSurface      = Color.White,
        ),
        content = content
    )
}
