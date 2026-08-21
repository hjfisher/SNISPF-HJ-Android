package com.snispf.android

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject

enum class ProxyStatus { STOPPED, STARTING, RUNNING, STOPPING, ERROR }

data class PoolStats(
    val activeSlots: Int = 0,
    val drainingSlots: Int = 0,
    val probedStable: Int = 0,
    val probedWeak: Int = 0,
    val probedDead: Int = 0,
    val probedTotal: Int = 0,
    val pairsTotal: Int = 0,
    val pairsProbed: Int = 0,
    val pairsUnprobed: Int = 0,
    val discoveryDone: Boolean = false,
    val staticIpsCount: Int = 0,
    val dynamicIpsFound: Int = 0,
    val dynamicDiscoveryEnabled: Boolean = false,
    val staticSnisCount: Int = 0,
    val dynamicSnisFound: Int = 0,
    val sniDynamicDiscoveryEnabled: Boolean = false,
    val quarantineSize: Int = 0,
    val sniQuarantineSize: Int = 0,
    val activeConnections: Int = 0,
    val totalConnections: Int = 0,
    val uptimeSeconds: Int = 0,
    val mitmFingerprint: String = "",
)

data class UiState(
    val status: ProxyStatus = ProxyStatus.STOPPED,
    val logs: List<String> = emptyList(),
    val configJson: String = DEFAULT_CONFIG,
    val listenPort: Int = 40443,
    val errorMessage: String? = null,
    val pool: PoolStats = PoolStats(),
)

private const val PREFS_NAME   = "snispf_prefs"
private const val KEY_CONFIG   = "config_json"

class SnispfViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(
        UiState(
            configJson = prefs.getString(KEY_CONFIG, DEFAULT_CONFIG) ?: DEFAULT_CONFIG,
        )
    )
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private var goBridge: GoBridge? = null
    private var pollJob: Job? = null

    init {
        try {
            val port = JSONObject(_uiState.value.configJson).optInt("LISTEN_PORT", 40443)
            updateState { copy(listenPort = port) }
        } catch (_: Exception) {}

        viewModelScope.launch(Dispatchers.IO) {
            try {
                goBridge = GoBridge(application)
            } catch (e: Exception) {
                updateState { copy(errorMessage = "Go bridge init failed: ${e.message}") }
            }
        }
    }

    fun start() {
        val state = _uiState.value
        viewModelScope.launch(Dispatchers.IO) {
            val bridge = goBridge ?: return@launch
            updateState { copy(status = ProxyStatus.STARTING, logs = emptyList(), errorMessage = null, pool = PoolStats()) }
            val result = bridge.start(state.configJson)
            when (result) {
                "ok", "already_running" -> {
                    SnispfService.start(getApplication())
                    startPolling()
                }
                else -> updateState { copy(status = ProxyStatus.ERROR, errorMessage = result) }
            }
        }
    }

    fun stop() {
        viewModelScope.launch(Dispatchers.IO) {
            goBridge?.stop()
            updateState { copy(status = ProxyStatus.STOPPING) }
            SnispfService.stop(getApplication())
        }
    }

    fun saveConfig(json: String) {
        val cleaned = try {
            val o = JSONObject(json)
            val alpn = o.opt("MITM_ALPN")
            if (alpn is String) {
                val arr = JSONArray()
                alpn.replace("[", "").replace("]", "")
                    .split(',', ';', '\n')
                    .map { it.trim().trim('"').trim('\'') }
                    .filter { it.isNotBlank() }
                    .distinct()
                    .forEach { arr.put(it) }
                o.put("MITM_ALPN", arr)
            }
            o.toString(2)
        } catch (_: Exception) { json }
        prefs.edit().putString(KEY_CONFIG, cleaned).apply()
        val port = try { JSONObject(cleaned).optInt("LISTEN_PORT", 40443) } catch (_: Exception) { 40443 }
        updateState { copy(configJson = cleaned, listenPort = port) }
    }

    fun clearLogs() {
        viewModelScope.launch(Dispatchers.IO) {
            goBridge?.clearLogs()
            updateState { copy(logs = emptyList()) }
        }
    }

    var isInForeground: Boolean = true

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch(Dispatchers.IO) {
            val bridge = goBridge ?: return@launch

            launch {
                bridge.status.collect { st ->
                    val status = when (st) {
                        "running"  -> ProxyStatus.RUNNING
                        "starting" -> ProxyStatus.STARTING
                        "stopping" -> ProxyStatus.STOPPING
                        "error"    -> ProxyStatus.ERROR
                        else       -> ProxyStatus.STOPPED
                    }
                    updateState { copy(status = status) }
                }
            }

            while (isActive) {
                if (isInForeground && bridge.status.value == "running") {
                    val goStats = bridge.stats.value
                    val pool = PoolStats(
                        activeSlots = goStats.poolActiveSlots,
                        drainingSlots = goStats.drainingSlots,
                        probedStable = goStats.probedStable,
                        probedWeak = goStats.probedWeak,
                        probedDead = goStats.probedDead,
                        probedTotal = goStats.probedTotal,
                        pairsTotal = goStats.pairsTotal,
                        pairsProbed = goStats.pairsProbed,
                        pairsUnprobed = goStats.pairsUnprobed,
                        discoveryDone = goStats.discoveryDone,
                        staticIpsCount = goStats.staticIpsCount,
                        dynamicIpsFound = goStats.dynamicIpsFound,
                        dynamicDiscoveryEnabled = goStats.dynamicDiscoveryEnabled,
                        staticSnisCount = goStats.staticSnisCount,
                        dynamicSnisFound = goStats.dynamicSnisFound,
                        sniDynamicDiscoveryEnabled = goStats.sniDynamicDiscoveryEnabled,
                        quarantineSize = goStats.quarantineSize,
                        sniQuarantineSize = goStats.sniQuarantineSize,
                        activeConnections = goStats.activeConnections,
                        totalConnections = goStats.totalConnections,
                        uptimeSeconds = goStats.uptimeSeconds,
                        mitmFingerprint = goStats.mitmFingerprint,
                    )
                    updateState { copy(logs = bridge.logs.value, pool = pool) }
                }
                delay(1000)
            }
        }
    }

    private fun updateState(block: UiState.() -> UiState) {
        _uiState.value = _uiState.value.block()
    }

    override fun onCleared() {
        super.onCleared()
        pollJob?.cancel()
        goBridge?.stop()
    }
}

const val DEFAULT_CONFIG = """{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_PORT": 443,
  "BYPASS_METHOD": "combined",
  "FRAGMENT_STRATEGY": "sni_split",
  "FRAGMENT_DELAY": 0.1,
  "FAKE_SNI_METHOD": "prefix_fake",
  "CIPHER_SUITES": "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
  "FINALMASK_TCP": [{"type": "fragment", "settings": {"packets": "tlshello", "lengths": ["50-100"], "delays": ["1-10"], "maxSplit": "10"}}],
  "MITM_CERT_FILE": null,
  "MITM_KEY_FILE": null,
  "MITM_CERT_CN": "SNISPF-HJ",
  "MITM_ALPN": ["h2", "http/1.1"],
  "MITM_USE_CLIENT_SNI": true,
  "FINGERPRINT": "unsafe",
  "ACTIVE_SLOTS": 10,
  "HEALTH_CHECK_INTERVAL": 30,
  "HEALTH_CHECK_TIMEOUT": 30,
  "PROBE_COUNT": 5,
  "LOSS_THRESHOLD": 0.20,
  "DEAD_THRESHOLD": 0.80,
  "DRAIN_TIMEOUT": 30.0,
  "MAX_DRAINING": 5,
  "EVICT_EVERY": 10,
  "EVICT_COUNT": 10,
  "RECYCLE_ENABLED": true,
  "RECYCLE_EVERY": 6,
  "RECYCLE_BATCH": 2,
  "RECYCLE_MIN_COOLDOWN": 180,
  "RECYCLE_MAX_QUARANTINE": 100,
  "QUARANTINE_SCOPE": "both",
  "SNI_EVICT_EVERY": 20,
  "SNI_EVICT_COUNT": 1,
  "SNI_RECYCLE_ENABLED": true,
  "SNI_RECYCLE_EVERY": 6,
  "SNI_RECYCLE_BATCH": 2,
  "SNI_RECYCLE_MIN_COOLDOWN": 180,
  "SNI_RECYCLE_MAX_QUARANTINE": 100,
  "SNI_QUARANTINE_SCOPE": "both",
  "FAKE_SNI_FRAGMENT_REAL": true,
  "DYNAMIC_SNI_DISCOVERY": false,
  "SNI_DISCOVERY_BATCH": 50,
  "SNI_DISCOVERY_INTERVAL": 120,
  "SNI_SOURCE_REFRESH_INTERVAL": 21600,
  "SNI_DISCOVERY_PROBE_TRIES": 3,
  "SNI_DISCOVERY_TIMEOUT": 2.0,
  "SNI_DISCOVERY_MIN_SUCCESS": 0.50,
  "MAX_DYNAMIC_SNIS": 100,
  "DYNAMIC_IP_DISCOVERY": false,
  "DISCOVERY_BATCH": 100,
  "DISCOVERY_INTERVAL": 120,
  "DISCOVERY_PROBE_TRIES": 3,
  "DISCOVERY_TIMEOUT": 2.0,
  "DISCOVERY_MIN_SUCCESS": 0.50,
  "DISCOVERY_MAX_IPS": 200,
  "CONNECT_IPS": [
    "172.66.41.252",
    "108.162.196.145",
    "172.65.13.230"
  ],
  "FAKE_SNIS": [
    "github.com",
    "google.com",
    "microsoft.com"
  ]
}"""