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
            val binaryFile = extractBinary()

            Log.d(TAG, "Starting Go binary: ${binaryFile.absolutePath}")

            val pb = ProcessBuilder(
                binaryFile.absolutePath,
                "--config", configFile.absolutePath,
                "--no-raw"
            )
                .directory(binDir)
                .redirectErrorStream(true)

            process = pb.start()
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

    private fun extractBinary(): File {
        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: "arm64-v8a"
        val binName = when (abi) {
            "arm64-v8a"                   -> "snispf-arm64"
            "armeabi-v7a", "armeabi"      -> "snispf-arm"
            "x86_64"                      -> "snispf-amd64"
            "x86"                         -> "snispf-x86"
            else                          -> "snispf-arm64"
        }

        val binFile = File(binDir, "snispf")
        if (binFile.exists()) binFile.delete()

        context.assets.open("bin/$binName").use { input ->
            binFile.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        // Set executable permission using Os.chmod (works on all Android versions)
        try {
            Os.chmod(binFile.absolutePath, 448) // 0o755 = 448 decimal
            Log.d(TAG, "Binary permissions set: ${binFile.canExecute()}")
        } catch (e: Exception) {
            Log.e(TAG, "chmod failed, trying setExecutable", e)
            binFile.setExecutable(true, false)
        }

        return binFile
    }

    private fun startReading() {
        readJob = scope.launch {
            try {
                val reader = BufferedReader(InputStreamReader(process?.inputStream ?: return@launch))
                var line: String? = null
                while (isActive && reader.readLine().also { line = it } != null) {
                    line?.let { processLine(it) }
                }
            } catch (e: Exception) {
                if (isActive) {
                    Log.e(TAG, "Read error", e)
                }
            } finally {
                _status.value = "stopped"
            }
        }
    }

    private fun processLine(line: String) {
        logBuffer.add(line)
        if (logBuffer.size > 500) logBuffer.removeAt(0)
        _logs.value = logBuffer.toList()

        parseStats(line)
        updateMitmFingerprint(line)
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