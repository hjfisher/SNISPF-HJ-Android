package com.snispf.android

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

enum class ProxyStatus { STOPPED, STARTING, RUNNING, STOPPING, ERROR }

data class PoolStats(
    val activeSlots: Int = 0,
    val drainingSlots: Int = 0,
    val probedStable: Int = 0,
    val probedWeak: Int = 0,
    val probedDead: Int = 0,
    val probedTotal: Int = 0,
    // Discovery — pairs_total GROWS as IPDiscovery injects new IPs
    val pairsTotal: Int = 0,
    val pairsProbed: Int = 0,
    val pairsUnprobed: Int = 0,
    val discoveryDone: Boolean = false,
    // IPDiscovery
    val dynamicIpsFound: Int = 0,
    val dynamicDiscoveryEnabled: Boolean = false,
    val quarantineSize: Int = 0,
    // Connections
    val activeConnections: Int = 0,
    val totalConnections: Int = 0,
    val uptimeSeconds: Int = 0,
)

data class UiState(
    val status: ProxyStatus = ProxyStatus.STOPPED,
    val logs: List<String> = emptyList(),
    val configJson: String = DEFAULT_CONFIG,
    val listenPort: Int = 40443,
    val useRoot: Boolean = false,
    val errorMessage: String? = null,
    val pool: PoolStats = PoolStats(),
)

private const val PREFS_NAME   = "snispf_prefs"
private const val KEY_CONFIG   = "config_json"
private const val KEY_USE_ROOT = "use_root"

class SnispfViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private val _uiState = MutableStateFlow(
        UiState(
            configJson = prefs.getString(KEY_CONFIG, DEFAULT_CONFIG) ?: DEFAULT_CONFIG,
            useRoot    = prefs.getBoolean(KEY_USE_ROOT, false),
        )
    )
    val uiState: StateFlow<UiState> = _uiState.asStateFlow()

    private var bridge: PyObject? = null
    private var pollJob: Job? = null

    init {
        try {
            val port = JSONObject(_uiState.value.configJson).optInt("LISTEN_PORT", 40443)
            updateState { copy(listenPort = port) }
        } catch (_: Exception) {}

        viewModelScope.launch(Dispatchers.IO) {
            try {
                bridge = Python.getInstance().getModule("bridge")
            } catch (e: Exception) {
                updateState { copy(errorMessage = "Python init failed: ${e.message}") }
            }
        }
    }

    fun start() {
        val state = _uiState.value
        viewModelScope.launch(Dispatchers.IO) {
            val b = bridge ?: return@launch
            updateState { copy(status = ProxyStatus.STARTING, logs = emptyList(), errorMessage = null, pool = PoolStats()) }
            val rootInt = if (state.useRoot) 1 else 0
            val result  = b.callAttr("start", state.configJson, rootInt).toString()
            when (result) {
                "ok", "already_running" -> {
                    // Start foreground service to prevent OS from killing the process
                    SnispfService.start(getApplication())
                    startPolling()
                }
                else -> updateState { copy(status = ProxyStatus.ERROR, errorMessage = result) }
            }
        }
    }

    fun stop() {
        viewModelScope.launch(Dispatchers.IO) {
            bridge?.callAttr("stop")
            updateState { copy(status = ProxyStatus.STOPPING) }
            SnispfService.stop(getApplication())
        }
    }

    fun saveConfig(json: String) {
        prefs.edit().putString(KEY_CONFIG, json).apply()
        val port = try { JSONObject(json).optInt("LISTEN_PORT", 40443) } catch (_: Exception) { 40443 }
        updateState { copy(configJson = json, listenPort = port) }
    }

    fun setUseRoot(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_USE_ROOT, enabled).apply()
        updateState { copy(useRoot = enabled) }
    }

    fun clearLogs() {
        viewModelScope.launch(Dispatchers.IO) {
            bridge?.callAttr("clear_logs")
            updateState { copy(logs = emptyList()) }
        }
    }

    // Track whether app is in foreground
    var isInForeground: Boolean = true

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                val b = bridge ?: break

                val statusStr = b.callAttr("get_status").toString()

                val status = when (statusStr) {
                    "running"  -> ProxyStatus.RUNNING
                    "starting" -> ProxyStatus.STARTING
                    "stopping" -> ProxyStatus.STOPPING
                    "error"    -> ProxyStatus.ERROR
                    else       -> ProxyStatus.STOPPED
                }

                if (status == ProxyStatus.STOPPED || status == ProxyStatus.ERROR) {
                    updateState { copy(status = status) }
                    break
                }

                // Only fetch logs and stats when app is visible
                if (isInForeground) {
                    val logsStr  = b.callAttr("get_logs").toString()
                    val statsStr = b.callAttr("get_stats").toString()

                    val logs = if (logsStr.isBlank()) emptyList()
                               else logsStr.split("\n").filter { it.isNotBlank() }

                    val m = statsStr.lines()
                        .filter { "=" in it }
                        .associate { it.substringBefore("=").trim() to it.substringAfter("=").trim() }

                    fun i(key: String) = m[key]?.toIntOrNull() ?: 0

                    val pool = PoolStats(
                        activeSlots             = i("pool_active_slots"),
                        drainingSlots           = i("pool_draining"),
                        probedStable            = i("probed_stable"),
                        probedWeak              = i("probed_weak"),
                        probedDead              = i("probed_dead"),
                        probedTotal             = i("probed_total"),
                        pairsTotal              = i("pairs_total"),
                        pairsProbed             = i("pairs_probed"),
                        pairsUnprobed           = i("pairs_unprobed"),
                        discoveryDone           = i("discovery_done") == 1,
                        dynamicIpsFound         = i("dynamic_ips_found"),
                        dynamicDiscoveryEnabled = i("dynamic_ip_discovery") == 1,
                        quarantineSize          = i("quarantine_size"),
                        activeConnections       = i("active_connections"),
                        totalConnections        = i("total_connections"),
                        uptimeSeconds           = i("uptime_seconds"),
                    )

                    updateState { copy(status = status, logs = logs, pool = pool) }
                    delay(1500)
                } else {
                    // Background: only keep-alive check every 10s, no UI updates
                    updateState { copy(status = status) }
                    delay(10_000)
                }
            }
        }
    }

    private fun updateState(block: UiState.() -> UiState) {
        _uiState.value = _uiState.value.block()
    }

    override fun onCleared() {
        super.onCleared()
        pollJob?.cancel()
        bridge?.callAttr("stop")
    }
}

const val DEFAULT_CONFIG = """{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_PORT": 443,
  "BYPASS_METHOD": "combined",
  "FRAGMENT_STRATEGY": "sni_split",
  "FRAGMENT_DELAY": 0.1,
  "USE_TTL_TRICK": false,
  "FAKE_SNI_METHOD": "prefix_fake",
  "ACTIVE_SLOTS": 3,
  "HEALTH_CHECK_INTERVAL": 30,
  "HEALTH_CHECK_TIMEOUT": 3,
  "PROBE_COUNT": 5,
  "LOSS_THRESHOLD": 0.20,
  "DEAD_THRESHOLD": 0.80,
  "DRAIN_TIMEOUT": 30.0,
  "MAX_DRAINING": 5,
  "EVICT_EVERY": 3,
  "EVICT_COUNT": 2,
  "RECYCLE_ENABLED": true,
  "RECYCLE_EVERY": 6,
  "RECYCLE_BATCH": 2,
  "RECYCLE_MIN_COOLDOWN": 180,
  "RECYCLE_MAX_QUARANTINE": 100,
  "QUARANTINE_SCOPE": "both",
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
