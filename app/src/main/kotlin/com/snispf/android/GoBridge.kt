package com.snispf.android

import android.content.Context
import android.os.Build
import android.system.Os
import android.util.Log
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

private const val TAG = "GoBridge"

data class GoStats(
    val poolActiveSlots: Int = 0,
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

class GoBridge(private val context: Context) {
    private var process: Process? = null
    private var readJob: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    private val _logs = MutableStateFlow<List<String>>(emptyList())
    val logs: StateFlow<List<String>> = _logs.asStateFlow()

    private val _stats = MutableStateFlow(GoStats())
    val stats: StateFlow<GoStats> = _stats.asStateFlow()

    private val _status = MutableStateFlow("stopped")
    val status: StateFlow<String> = _status.asStateFlow()

    private val logBuffer = mutableListOf<String>()
    private val statsMap = mutableMapOf<String, String>()

    private val binDir: File by lazy {
        context.getDir("bin", Context.MODE_PRIVATE).also { it.mkdirs() }
    }

    fun start(configJson: String): String {
        if (process != null) return "already_running"

        return try {
            _status.value = "starting"
            logBuffer.clear()
            statsMap.clear()

            val configFile = writeConfig(configJson)
            val binaryFile = getBinary()

            Log.d(TAG, "=== Diagnostics ===")
            Log.d(TAG, "ABI: ${Build.SUPPORTED_ABIS.firstOrNull()}")
            Log.d(TAG, "nativeLibDir: ${context.applicationInfo.nativeLibraryDir}")
            Log.d(TAG, "Binary: ${binaryFile.absolutePath}")
            Log.d(TAG, "  exists=${binaryFile.exists()} canExec=${binaryFile.canExecute()} length=${binaryFile.length()}")
            Log.d(TAG, "Config: ${configFile.absolutePath}")
            Log.d(TAG, "===================")

            val cmd = arrayOf(
                binaryFile.absolutePath,
                "--config", configFile.absolutePath,
                "--no-raw"
            )

            Log.d(TAG, "Executing: ${cmd.joinToString(" ")}")

            process = Runtime.getRuntime().exec(cmd)
            startReading()

            "ok"
        } catch (e: Exception) {
            Log.e(TAG, "Start failed", e)
            _status.value = "error"
            "error: ${e.message}"
        }
    }

    fun stop() {
        process?.let {
            try {
                it.destroy()
            } catch (_: Exception) {}
        }
        process = null
        readJob?.cancel()
        _status.value = "stopped"
    }

    fun clearLogs() {
        logBuffer.clear()
        _logs.value = emptyList()
    }

    private fun writeConfig(configJson: String): File {
        val configFile = File(binDir, "config.json")
        configFile.writeText(configJson)
        return configFile
    }

    private fun getBinary(): File {
        // Android extracts jniLibs to nativeLibraryDir with execute permissions
        val binaryFile = File(context.applicationInfo.nativeLibraryDir, "libsnispf.so")
        if (!binaryFile.exists()) {
            throw IllegalStateException("Native library not found: ${binaryFile.absolutePath}")
        }
        return binaryFile
    }

    private fun startReading() {
        readJob = scope.launch {
            try {
                val p = process ?: return@launch
                val reader = BufferedReader(InputStreamReader(p.inputStream))

                var line: String? = null
                while (isActive && reader.readLine().also { line = it } != null) {
                    line?.let { processLine(it) }
                }

                val exitCode = p.waitFor()
                Log.d(TAG, "Process exited with code: $exitCode")
                addLog("[exit code: $exitCode]")

                _status.value = "stopped"
            } catch (e: Exception) {
                Log.e(TAG, "Read error", e)
                if (isActive) {
                    _status.value = "stopped"
                }
            }
        }
    }

    private fun processLine(line: String) {
        Log.d(TAG, "GO> $line")
        logBuffer.add(line)
        if (logBuffer.size > 500) logBuffer.removeAt(0)
        _logs.value = logBuffer.toList()

        parseStats(line)
        updateMitmFingerprint(line)
    }

    private fun addLog(line: String) {
        logBuffer.add(line)
        if (logBuffer.size > 500) logBuffer.removeAt(0)
        _logs.value = logBuffer.toList()
    }

    private fun parseStats(line: String) {
        when {
            line.contains("pool active") || line.contains("Connection pool active") -> {
                val pairs = Regex("(\\d+) pair\\(s\\)").find(line)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                val slots = Regex("(\\d+) active slot").find(line)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                statsMap["pairs_total"] = pairs.toString()
                statsMap["pool_active_slots"] = slots.toString()
            }
            line.contains("IP-only") && line.contains("IP(s)") -> {
                val ips = Regex("(\\d+) IP\\(s\\)").find(line)?.groupValues?.get(1)?.toIntOrNull() ?: 0
                statsMap["static_ips_count"] = ips.toString()
            }
            line.contains("Dynamic IP discovery active") -> {
                statsMap["dynamic_ip_discovery"] = "1"
            }
            line.contains("Dynamic SNI discovery active") -> {
                statsMap["dynamic_sni_discovery"] = "1"
            }
            line.contains("MITM cert SHA-256") -> {
                val fp = line.substringAfter(":", "").trim()
                if (fp.isNotBlank()) statsMap["mitm_fingerprint"] = fp
            }
        }

        val pool = GoStats(
            poolActiveSlots = statsMap["pool_active_slots"]?.toIntOrNull() ?: 0,
            pairsTotal = statsMap["pairs_total"]?.toIntOrNull() ?: 0,
            staticIpsCount = statsMap["static_ips_count"]?.toIntOrNull() ?: 0,
            dynamicDiscoveryEnabled = statsMap["dynamic_ip_discovery"] == "1",
            sniDynamicDiscoveryEnabled = statsMap["dynamic_sni_discovery"] == "1",
            mitmFingerprint = statsMap["mitm_fingerprint"] ?: "",
        )
        _stats.value = pool
    }

    private fun updateMitmFingerprint(line: String) {
        if (line.contains("SHA-256")) {
            val fp = line.substringAfter(":", "").trim()
            if (fp.isNotBlank() && fp.length == 64) {
                statsMap["mitm_fingerprint"] = fp
                _stats.value = _stats.value.copy(mitmFingerprint = fp)
            }
        }
    }
}