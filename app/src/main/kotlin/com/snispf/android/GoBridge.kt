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
import java.util.concurrent.TimeUnit

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
    val ipDiscoveryReason: String = "",
    val sniDiscoveryReason: String = "",
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
    private var startedAtMillis: Long = 0
    private var activeConnAccum = 0
    private var totalConnCount = 0
    private var lastUseRoot = false

    private val binDir: File by lazy {
        context.getDir("bin", Context.MODE_PRIVATE).also { it.mkdirs() }
    }

    private val homeDir: File by lazy {
        context.filesDir.also { it.mkdirs() }
    }

    /** Check whether the device has root access (su binary + working su). */
    fun checkRoot(): Boolean {
        return try {
            val p = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val output = BufferedReader(InputStreamReader(p.inputStream)).readText()
            val exit = p.waitFor(3, TimeUnit.SECONDS)
            exit && output.contains("uid=0")
        } catch (_: Exception) { false }
    }

    fun start(configJson: String, useRoot: Boolean = false): String {
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
            Log.d(TAG, "HOME: ${homeDir.absolutePath}")
            Log.d(TAG, "Root: $useRoot")
            Log.d(TAG, "===================")

            lastUseRoot = useRoot
            // Reap any backend left over from a previous session (crash, force-stop,
            // or sticky service) so it cannot keep the listen port bound and make
            // this fresh start fail.
            reapBackend()

            val pb: ProcessBuilder
            if (useRoot) {
                // Su drops into a shell. Use `exec` so the su process is REPLACED by
                // our binary — the Process we hold then refers to the real backend,
                // so destroying it later actually kills the backend (no orphaned child).
                // Under root we omit --no-raw so AF_PACKET raw injection can engage
                // for the fake_sni/combined methods.
                val binPath = binaryFile.absolutePath
                val cfgPath = configFile.absolutePath
                val homePath = homeDir.absolutePath
                // --home guarantees a writable cert-cache dir even though su
                // sanitizes $HOME to root's (often read-only) location.
                val cmdLine = "exec \"$binPath\" --config \"$cfgPath\" --home \"$homePath\" 2>&1"
                pb = ProcessBuilder("su", "-c", cmdLine).apply {
                    environment()["HOME"] = homePath
                    redirectErrorStream(true)
                }
            } else {
                // Without root, AF_PACKET is unavailable (EPERM); keep raw injection
                // explicitly off so it never attempts and logs a failure loop.
                val cmd = arrayOf(
                    binaryFile.absolutePath, "--config",
                    configFile.absolutePath, "--home",
                    homeDir.absolutePath, "--no-raw"
                )
                pb = ProcessBuilder(*cmd).apply {
                    directory(binDir)
                    environment()["HOME"] = homeDir.absolutePath
                    environment()["USERPROFILE"] = homeDir.absolutePath
                    redirectErrorStream(true)
                }
            }

            Log.d(TAG, "Executing: ${if (useRoot) "su -c ..." else pb.command().joinToString(" ")}")

            process = pb.start()
            lastUseRoot = useRoot
            startedAtMillis = System.currentTimeMillis()
            activeConnAccum = 0
            totalConnCount = 0
            startReading()

            "ok"
        } catch (e: Exception) {
            Log.e(TAG, "Start failed", e)
            _status.value = "error"
            "error: ${e.message}"
        }
    }

    fun stop() {
        val p = process
        process = null
        readJob?.cancel()
        readJob = null

        if (p != null) {
            try {
                // 1. SIGTERM (graceful)
                p.destroy()
                // 2. Wait briefly for clean exit
                if (!p.waitFor(500, TimeUnit.MILLISECONDS)) {
                    // 3. SIGKILL (forcible)
                    p.destroyForcibly()
                    p.waitFor(1, TimeUnit.SECONDS)
                }
            } catch (_: Exception) {}

            // 4. Last resort: kill by PID via reflection on the process object
            if (p.isAlive) {
                try {
                    val pid = processPid(p)
                    if (pid > 0) {
                        Log.w(TAG, "Process still alive after SIGKILL, killing PID $pid")
                        android.os.Process.killProcess(pid)
                        p.waitFor(500, TimeUnit.MILLISECONDS)
                        if (p.isAlive) p.destroyForcibly()
                    } else {
                        p.destroyForcibly()
                    }
                } catch (_: Exception) {
                    try { p.destroyForcibly() } catch (_: Exception) {}
                }
            }
        }

        // 5. Reap any lingering backend so the listen port is freed. This is the
        //    critical step for root mode: su may fork the binary, orphaning it so
        //    the Process above only killed `su`, while the backend keeps the port
        //    open and bricks the next start.
        reapBackend()

        _status.value = "stopped"
    }

    /**
     * Aggressively terminate every lingering instance of our bundled backend.
     * Works two ways:
     *   - root: run `su -c pkill -9 -f <binPath>` (kills any uid, incl. orphans).
     *   - non-root: walk /proc and kill same-UID processes whose exe is the binary
     *     (available when the app UID is unchanged; AF_PACKET case).
     */
    private fun reapBackend() {
        val binPath = try { getBinary().absolutePath } catch (_: Exception) { "" }
        val binName = binPath.substringAfterLast('/')

        if (lastUseRoot) {
            try {
                val script = "pkill -9 -f '$binPath' 2>/dev/null; pkill -9 -f '$binName' 2>/dev/null; true"
                val pk = ProcessBuilder("su", "-c", script).start()
                pk.waitFor(2, TimeUnit.SECONDS)
                Log.d(TAG, "Root pkill issued for '$binName'")
            } catch (_: Exception) {}
        }

        // /proc walk — belt and suspenders; also covers the non-root socket JIT case.
        try {
            val procs = File("/proc").listFiles() ?: return
            for (dir in procs) {
                val pid = dir.name.toIntOrNull() ?: continue
                if (pid <= 0 || pid == android.os.Process.myPid()) continue
                val exe = File(dir, "exe")
                val resolved = try { exe.canonicalPath } catch (_: Exception) { "" }
                val cmdline = try { File(dir, "cmdline").readText().trimEnd('\u0000') } catch (_: Exception) { "" }
                if (resolved == binPath || cmdline.contains(binName)) {
                    try {
                        android.os.Process.killProcess(pid)
                        Log.w(TAG, "Reaped lingering backend pid=$pid")
                    } catch (_: Exception) {}
                }
            }
        } catch (_: Exception) {}
    }

    /** Best-effort retrieval of the underlying native PID of a Java Process. */
    private fun processPid(p: Process): Int {
        return try {
            val f = p.javaClass.getDeclaredField("pid")
            f.isAccessible = true
            f.getInt(p)
        } catch (_: Exception) {
            try {
                // Some ART versions expose the PID as a Method instead
                val m = p.javaClass.getDeclaredMethod("pid")
                m.isAccessible = true
                m.invoke(p) as? Int ?: -1
            } catch (_: Exception) { -1 }
        }
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
                var firstLine = true
                while (isActive && reader.readLine().also { line = it } != null) {
                    if (firstLine) {
                        _status.value = "running"
                        firstLine = false
                    }
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
    }

    private fun addLog(line: String) {
        logBuffer.add(line)
        if (logBuffer.size > 500) logBuffer.removeAt(0)
        _logs.value = logBuffer.toList()
    }

    private fun parseStats(line: String) {
        when {
            // Machine-readable snapshot printed every 5s by the Go binary.
            // Authoritative — overrides everything derived from other lines.
            line.contains("STATS ") -> {
                for (m in Regex("(\\w+)=(\\d+)").findAll(line)) {
                    val mapped = when (m.groupValues[1]) {
                        "pairs"          -> "pairs_total"
                        "stable"         -> "probed_stable"
                        "weak"           -> "probed_weak"
                        "dead"           -> "probed_dead"
                        "unprobed"       -> "pairs_unprobed"
                        "slots"          -> "pool_active_slots"
                        "draining"       -> "pool_draining"
                        "active_conns"   -> "active_connections"
                        "total_conns"    -> "total_connections"
                        "static_ips"     -> "static_ips_count"
                        "dynamic_ips"    -> "dynamic_ips_found"
                        "static_snis"    -> "static_snis_count"
                        "dynamic_snis"   -> "dynamic_snis_found"
                        "ip_quarantine"  -> "quarantine_ips"
                        "sni_quarantine" -> "quarantine_snis"
                        else             -> null
                    }
                    if (mapped != null) statsMap[mapped] = m.groupValues[2]
                }
            }
            // "Connection pool active -- N pair(s), M active slot(s)"
            line.contains("Connection pool active") && line.contains("pair(s)") -> {
                statsMap["pairs_total"] = Regex("(\\d+) pair\\(s\\)").find(line)?.groupValues?.get(1) ?: ""
                statsMap["pool_active_slots"] = Regex("(\\d+) active slot").find(line)?.groupValues?.get(1) ?: ""
            }
            // "Connection pool active (IP-only) -- N IP(s), M active slot(s)"
            line.contains("Connection pool active") && line.contains("IP(s)") -> {
                statsMap["static_ips_count"] = Regex("(\\d+) IP\\(s\\)").find(line)?.groupValues?.get(1) ?: ""
                statsMap["pool_active_slots"] = Regex("(\\d+) active slot").find(line)?.groupValues?.get(1) ?: ""
            }
            // "Upstream selection: POOL (N pair(s), M active slot(s))"
            line.contains("Upstream selection: POOL") -> {
                statsMap["pairs_total"] = Regex("(\\d+) pair\\(s\\)").find(line)?.groupValues?.get(1) ?: ""
                statsMap["pool_active_slots"] = Regex("(\\d+) active slot").find(line)?.groupValues?.get(1) ?: ""
            }
            // "Pool summary — known=K stable=S weak=W dead=D unexplored=U"
            line.contains("Pool summary") -> {
                Regex("known=(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["pairs_total"] = it }
                Regex("stable=(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["probed_stable"] = it }
                Regex("weak=(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["probed_weak"] = it }
                Regex("dead=(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["probed_dead"] = it }
                Regex("unexplored=(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["pairs_unprobed"] = it }
                activeConnAccum = 0
            }
            // Pool table row: "... loss=X% latency=Nms score=Y active=N"
            line.contains("loss=") && line.contains("score=") && line.contains("active=") -> {
                Regex("active=(\\d+)").find(line)?.groupValues?.get(1)?.toIntOrNull()?.let { activeConnAccum += it }
            }
            // "All combinations explored — reshuffling for next cycle."
            line.contains("All combinations explored") -> statsMap["discovery_done"] = "1"
            // "IP discovery status — dynamic IPs: D / MAX  total known: K"
            line.contains("IP discovery status") -> {
                Regex("dynamic IPs:\\s*(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["dynamic_ips_found"] = it }
            }
            // "SNI discovery status — dynamic SNIs: D / MAX  total known: K  candidate pool: C"
            line.contains("SNI discovery status") -> {
                Regex("dynamic SNIs:\\s*(\\d+)").find(line)?.groupValues?.get(1)?.let { statsMap["dynamic_snis_found"] = it }
            }
            line.contains("Dynamic IP discovery active") -> {
                statsMap["dynamic_ip_discovery"] = "1"
                statsMap.remove("ip_discovery_reason")
            }
            line.contains("IP discovery enabled but no FAKE_SNIS") ->
                statsMap["ip_discovery_reason"] = "on, but FAKE_SNIS is empty"
            line.contains("Dynamic IP discovery: disabled") ->
                statsMap["ip_discovery_reason"] = "off in config (DYNAMIC_IP_DISCOVERY=false)"
            line.contains("Dynamic SNI discovery active") -> {
                statsMap["dynamic_sni_discovery"] = "1"
                statsMap.remove("sni_discovery_reason")
            }
            line.contains("Dynamic SNI discovery: skipped") ->
                statsMap["sni_discovery_reason"] =
                    if (line.contains("MITM")) "skipped — IP-only pool in MITM mode"
                    else "skipped — IP-only pool for this method"
            line.contains("Dynamic SNI discovery: disabled") ->
                statsMap["sni_discovery_reason"] = "off in config (DYNAMIC_SNI_DISCOVERY=false)"
            // Quarantine tracking (best effort)
            line.contains("Evicted IP") && line.contains("quarantine") ->
                statsMap["quarantine_ips"] = ((statsMap["quarantine_ips"]?.toIntOrNull() ?: 0) + 1).toString()
            line.contains("Recycled IP") ->
                statsMap["quarantine_ips"] = maxOf(0, (statsMap["quarantine_ips"]?.toIntOrNull() ?: 0) - 1).toString()
            line.contains("Evicted SNI") && line.contains("quarantine") ->
                statsMap["quarantine_snis"] = ((statsMap["quarantine_snis"]?.toIntOrNull() ?: 0) + 1).toString()
            line.contains("Recycled SNI") ->
                statsMap["quarantine_snis"] = maxOf(0, (statsMap["quarantine_snis"]?.toIntOrNull() ?: 0) - 1).toString()
            // "MITM cert SHA-256 (pin this): <fp>" — extract the bare 64-hex hash;
            // substringAfter(":") would grab the log timestamp's colons first.
            line.contains("MITM cert SHA-256") -> {
                Regex("[0-9a-fA-F]{64}").find(line)?.value?.let {
                    statsMap["mitm_fingerprint"] = it
                }
            }
            // Bare 64-hex line (from the MITM banner print)
            Regex("^[0-9a-fA-F]{64}$").containsMatchIn(line.trim()) ->
                statsMap["mitm_fingerprint"] = line.trim()
        }

        val stable = statsMap["probed_stable"]?.toIntOrNull() ?: 0
        val weak = statsMap["probed_weak"]?.toIntOrNull() ?: 0
        val dead = statsMap["probed_dead"]?.toIntOrNull() ?: 0

        _stats.value = GoStats(
            poolActiveSlots = statsMap["pool_active_slots"]?.toIntOrNull() ?: 0,
            drainingSlots = statsMap["pool_draining"]?.toIntOrNull() ?: 0,
            probedStable = stable,
            probedWeak = weak,
            probedDead = dead,
            probedTotal = stable + weak + dead,
            pairsTotal = statsMap["pairs_total"]?.toIntOrNull() ?: 0,
            pairsProbed = stable + weak + dead,
            pairsUnprobed = statsMap["pairs_unprobed"]?.toIntOrNull() ?: 0,
            discoveryDone = statsMap["discovery_done"] == "1",
            staticIpsCount = statsMap["static_ips_count"]?.toIntOrNull() ?: 0,
            dynamicIpsFound = statsMap["dynamic_ips_found"]?.toIntOrNull() ?: 0,
            dynamicDiscoveryEnabled = statsMap["dynamic_ip_discovery"] == "1",
            staticSnisCount = statsMap["static_snis_count"]?.toIntOrNull() ?: 0,
            dynamicSnisFound = statsMap["dynamic_snis_found"]?.toIntOrNull() ?: 0,
            sniDynamicDiscoveryEnabled = statsMap["dynamic_sni_discovery"] == "1",
            quarantineSize = statsMap["quarantine_ips"]?.toIntOrNull() ?: 0,
            sniQuarantineSize = statsMap["quarantine_snis"]?.toIntOrNull() ?: 0,
            activeConnections = statsMap["active_connections"]?.toIntOrNull() ?: activeConnAccum,
            totalConnections = statsMap["total_connections"]?.toIntOrNull() ?: totalConnCount,
            uptimeSeconds = if (startedAtMillis > 0)
                ((System.currentTimeMillis() - startedAtMillis) / 1000).toInt() else 0,
            mitmFingerprint = statsMap["mitm_fingerprint"] ?: "",
            ipDiscoveryReason = statsMap["ip_discovery_reason"] ?: "",
            sniDiscoveryReason = statsMap["sni_discovery_reason"] ?: "",
        )
    }
}
