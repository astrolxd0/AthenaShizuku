package com.kin.athena.service.shizuku

import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.ComponentName
import android.content.ServiceConnection
import android.os.Binder
import android.os.IBinder
import com.kin.athena.BuildConfig
import com.kin.athena.core.logging.Logger
import com.kin.athena.domain.model.Application
import com.kin.athena.domain.usecase.application.ApplicationUseCases
import com.kin.athena.domain.usecase.preferences.PreferencesUseCases
import com.kin.athena.domain.usecase.networkFilter.NetworkFilterUseCases
import com.kin.athena.domain.usecase.log.LogUseCases
import com.kin.athena.domain.model.Log
import com.kin.athena.service.firewall.model.FirewallResult
import com.kin.athena.service.firewall.utils.FirewallStatus
import com.kin.athena.service.utils.manager.FirewallManager
import com.kin.athena.service.utils.manager.FirewallService
import com.kin.athena.service.utils.notifications.showStartNotification
import dagger.hilt.android.AndroidEntryPoint
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import rikka.shizuku.Shizuku
import java.util.Collections
import javax.inject.Inject

/**
 * Shizuku-backed firewall.
 *
 * Android's FIREWALL_CHAIN_OEM_DENY_3 is a deny-list: enabling it blocks nothing
 * until packages are explicitly added. So on start we enable the chain and then
 * push a deny for every app whose access is switched off, and on stop we lift
 * those denies before disabling the chain.
 */
@AndroidEntryPoint
class ShizukuConnectionService : Service(), CoroutineScope by CoroutineScope(Dispatchers.IO), FirewallService {

    @Inject lateinit var applicationUseCases: ApplicationUseCases
    @Inject lateinit var preferencesUseCases: PreferencesUseCases
    @Inject lateinit var networkFilterUseCases: NetworkFilterUseCases
    @Inject lateinit var logUseCases: LogUseCases
    @Inject lateinit var firewallManager: FirewallManager
    @Inject @ApplicationContext lateinit var appContext: Context

    private var installedApplications: List<Application>? = null
    private var isLoggingEnabled = false
    private var tcpLoggerJob: kotlinx.coroutines.Job? = null
    private var udpLoggerJob: kotlinx.coroutines.Job? = null

    // Track logged connections to avoid duplicates
    private val loggedConnections = mutableSetOf<String>()

    // Packages we currently hold a deny bit for on the OEM_DENY_3 chain.
    private val deniedPackages: MutableSet<String> = Collections.synchronizedSet(mutableSetOf())

    private val binder = LocalBinder()

    // The AIDL-bound interface to your user service
    private var shizukuFirewallService: IShizukuFirewallService? = null
    private var isServiceBound = false

    private val serviceArgs by lazy {
        Shizuku.UserServiceArgs(
            ComponentName(appContext.packageName, ShizukuFirewallUserService::class.java.name)
        )
            .processNameSuffix("firewall_service")
            .debuggable(BuildConfig.DEBUG)
            // Bumping the version makes Shizuku restart a cached user service after an app update.
            .version(BuildConfig.VERSION_CODE)
    }

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName, service: IBinder) {
            Logger.debug("ShizukuConnectionService: Shizuku user service connected")
            shizukuFirewallService = IShizukuFirewallService.Stub.asInterface(service)
            isServiceBound = true

            // Binder calls block, keep them off the main thread.
            launch { applyInitialRules() }
        }

        override fun onServiceDisconnected(name: ComponentName) {
            Logger.warn("ShizukuConnectionService: Shizuku user service disconnected")
            shizukuFirewallService = null
            isServiceBound = false
            // Stop logging jobs since service is disconnected
            stopPacketLogging()
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Logger.info("ShizukuConnectionService: onStartCommand called")
        return START_STICKY
    }

    override fun onCreate() {
        super.onCreate()
        Logger.info("ShizukuConnectionService: onCreate")
        // Note: this Android-managed instance is created by FirewallManager.bindService()
        // while the Hilt singleton instance is already LOADING. Do not reset the status here.
    }

    override fun onDestroy() {
        super.onDestroy()
        Logger.info("ShizukuConnectionService: onDestroy")
        firewallManager.update(FirewallStatus.OFFLINE)
        unbindUserService()
    }

    override fun startService(context: Context) {
        Logger.info("ShizukuConnectionService: startService called")
        firewallManager.update(FirewallStatus.LOADING(0f))
        context.startService(Intent(context, ShizukuConnectionService::class.java))
        launch {
            bindUserService()
        }
    }

    override fun stopService(context: Context) {
        Logger.info("ShizukuConnectionService: stopService called")

        stopPacketLogging()
        firewallManager.update(FirewallStatus.OFFLINE)

        launch {
            // Lift our denies and disable the chain BEFORE dropping the user service,
            // otherwise the rules outlive the firewall.
            tearDownRules()
            unbindUserService()
            context.stopService(Intent(context, ShizukuConnectionService::class.java))
        }
    }

    override fun updateRules(application: Application?) {
        application?.let { app ->
            launch {
                setAppNetworking(app)
            }
        }
    }

    override fun updateLogs(enabled: Boolean) {
        Logger.info("ShizukuConnectionService: updateLogs($enabled)")
        isLoggingEnabled = enabled

        if (enabled) {
            Logger.info("Shizuku firewall logging started")
            startPacketLogging()
        } else {
            Logger.info("Shizuku firewall logging stopped")
            stopPacketLogging()
        }
    }

    override fun updateScreen(value: Boolean) {
        Logger.debug("ShizukuConnectionService: updateScreen($value) not implemented yet")
    }

    override suspend fun updateDomains(progressCallback: (suspend (Int) -> Unit)?) {
        Logger.debug("ShizukuConnectionService: updateDomains not implemented yet")
    }

    override fun updateHttpSettings() {
        Logger.debug("ShizukuConnectionService: updateHttpSettings not implemented yet")
    }

    override fun setDnsBlocking(enabled: Boolean) {
        Logger.debug("ShizukuConnectionService: setDnsBlocking($enabled) not implemented yet")
    }

    override fun isDnsBlockingEnabled(): Boolean {
        return false
    }

    private fun bindUserService() {
        if (!Shizuku.pingBinder()) {
            Logger.warn("ShizukuConnectionService: Shizuku not running")
            firewallManager.update(FirewallStatus.OFFLINE)
            return
        }
        if (Shizuku.checkSelfPermission() != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            Logger.warn("ShizukuConnectionService: Shizuku permission not granted")
            firewallManager.update(FirewallStatus.OFFLINE)
            return
        }
        if (isServiceBound && shizukuFirewallService != null) {
            Logger.debug("ShizukuConnectionService: user service already bound, re-applying rules")
            launch { applyInitialRules() }
            return
        }
        try {
            Shizuku.bindUserService(serviceArgs, connection)
            Logger.debug("ShizukuConnectionService: binding user service")
        } catch (e: Exception) {
            Logger.error("ShizukuConnectionService: failed to bind user service: ${e.message}")
            firewallManager.update(FirewallStatus.OFFLINE)
        }
    }

    private fun unbindUserService() {
        if (isServiceBound) {
            try {
                Shizuku.unbindUserService(serviceArgs, connection, true)
                Logger.debug("ShizukuConnectionService: unbound user service")
            } catch (e: Exception) {
                Logger.error("ShizukuConnectionService: error unbinding: ${e.message}")
            } finally {
                isServiceBound = false
                shizukuFirewallService = null
            }
        }
    }

    /**
     * Enables the deny chain and pushes a deny for every app whose access is off.
     * Runs on the IO dispatcher once the user service is connected.
     */
    private suspend fun applyInitialRules() {
        val svc = shizukuFirewallService
        if (svc == null) {
            Logger.warn("ShizukuConnectionService: cannot apply rules — user service not bound")
            firewallManager.update(FirewallStatus.OFFLINE)
            return
        }

        try {
            if (!svc.enableFirewallChain()) {
                Logger.error("ShizukuConnectionService: enableFirewallChain failed — is `cmd connectivity set-chain3-enabled` available on this device?")
                firewallManager.update(FirewallStatus.OFFLINE)
                return
            }
            Logger.info("ShizukuConnectionService: firewall chain enabled")
            firewallManager.update(FirewallStatus.LOADING(0.05f))

            loadApplications()
            val apps = installedApplications ?: emptyList()
            val toDeny = apps.filter { !it.isAllowed() }.map { it.packageID }
            Logger.info("ShizukuConnectionService: applying deny rules for ${toDeny.size}/${apps.size} apps")

            deniedPackages.clear()
            toDeny.forEachIndexed { index, packageName ->
                if (svc.setPackageNetworking(packageName, false)) {
                    deniedPackages.add(packageName)
                }
                val progress = 0.05f + 0.9f * (index + 1) / toDeny.size.coerceAtLeast(1)
                firewallManager.update(FirewallStatus.LOADING(progress))
            }
            Logger.info("ShizukuConnectionService: ${deniedPackages.size}/${toDeny.size} deny rules applied")

            installedApplications?.let { showStartNotification(it, preferencesUseCases, appContext) }
            firewallManager.update(FirewallStatus.ONLINE)

            // Start logging automatically like root service does
            if (::logUseCases.isInitialized) {
                isLoggingEnabled = true
                startPacketLogging()
            } else {
                Logger.error("ShizukuConnectionService: Cannot start logging - logUseCases not initialized!")
            }
        } catch (e: Exception) {
            Logger.error("ShizukuConnectionService: exception applying rules: ${e.message}")
            firewallManager.update(FirewallStatus.OFFLINE)
        }
    }

    /**
     * Lifts every deny we own and disables the chain. Safe to call when unbound.
     */
    private fun tearDownRules() {
        val svc = shizukuFirewallService
        if (svc == null) {
            Logger.warn("ShizukuConnectionService: cannot tear down rules — user service not bound")
            deniedPackages.clear()
            return
        }
        try {
            val denied = synchronized(deniedPackages) { deniedPackages.toList() }
            if (denied.isNotEmpty()) {
                val restored = svc.setPackagesNetworking(denied, true)
                Logger.info("ShizukuConnectionService: restored networking for $restored/${denied.size} apps")
            }
            deniedPackages.clear()

            if (svc.disableFirewallChain()) {
                Logger.info("ShizukuConnectionService: firewall chain disabled")
            } else {
                Logger.warn("ShizukuConnectionService: disableFirewallChain returned false")
            }
        } catch (e: Exception) {
            Logger.error("ShizukuConnectionService: exception tearing down rules: ${e.message}")
        }
    }

    private suspend fun loadApplications() {
        withContext(Dispatchers.IO) {
            applicationUseCases.getApplications.execute().fold(
                ifSuccess = {
                    installedApplications = it
                },
                ifFailure = { err ->
                    Logger.error("ShizukuConnectionService: failed to load apps: ${err.message}")
                }
            )
        }
    }

    private fun startPacketLogging() {
        if (!isLoggingEnabled) return

        // Cancel any existing jobs first
        stopPacketLogging()

        // Check if service is bound before starting
        if (!isServiceBound || shizukuFirewallService == null) {
            Logger.warn("Cannot start packet logging: Shizuku service not bound yet")
            return
        }

        tcpLoggerJob = launch {
            try {
                Logger.info("Starting TCP packet logging via Shizuku")
                monitorNetworkConnections("tcp")
            } catch (e: Exception) {
                Logger.error("TCP packet logging failed: ${e.message}")
            }
        }

        udpLoggerJob = launch {
            try {
                Logger.info("Starting UDP packet logging via Shizuku")
                monitorNetworkConnections("udp")
            } catch (e: Exception) {
                Logger.error("UDP packet logging failed: ${e.message}")
            }
        }
    }

    private fun stopPacketLogging() {
        tcpLoggerJob?.cancel()
        udpLoggerJob?.cancel()
        tcpLoggerJob = null
        udpLoggerJob = null
        loggedConnections.clear()
        Logger.info("Stopped packet logging")
    }

    private suspend fun monitorNetworkConnections(protocol: String) {
        while (isLoggingEnabled && isServiceBound) {
            try {
                val svc = shizukuFirewallService
                if (svc == null) {
                    Logger.warn("Shizuku service became null during $protocol monitoring")
                    kotlinx.coroutines.delay(1000)
                    continue
                }

                val result = svc.executeCommand("cat /proc/net/$protocol")
                if (result.isNotEmpty()) {
                    Logger.debug("Received $protocol data: ${result.lines().size} lines")
                    parseNetworkConnections(result, protocol.uppercase())
                } else {
                    Logger.warn("Empty result from /proc/net/$protocol")
                }
                kotlinx.coroutines.delay(1000)
            } catch (e: Exception) {
                Logger.error("Error monitoring $protocol connections: ${e.message}")
                kotlinx.coroutines.delay(5000)
            }
        }
        Logger.info("Stopped monitoring $protocol connections")
    }

    private fun parseNetworkConnections(data: String, protocol: String) {
        if (!isLoggingEnabled) return

        launch {
            try {
                data.lines().drop(1).forEach { line ->
                    if (line.trim().isNotEmpty()) {
                        parseConnectionLine(line, protocol)
                    }
                }
            } catch (e: Exception) {
                Logger.error("Error parsing network connections: ${e.message}")
            }
        }
    }

    private fun parseConnectionLine(line: String, protocol: String) {
        try {
            val parts = line.trim().split("\\s+".toRegex())
            if (parts.size < 8) return

            val localAddress = parts[1]
            val remoteAddress = parts[2]
            val uid = parts[7].toIntOrNull() ?: return

            val (sourceIP, sourcePort) = parseAddress(localAddress)
            val (destIP, destPort) = parseAddress(remoteAddress)

            if (destIP != "0.0.0.0" && destPort != "0") {
                // Create unique key for this connection to avoid duplicates
                val connectionKey = "$protocol:$uid:$destIP:$destPort"

                // Skip if already logged
                if (loggedConnections.contains(connectionKey)) {
                    return
                }

                val app = installedApplications?.firstOrNull { it.uid == uid }
                // The Shizuku chain blocks all networking when either toggle is off.
                val isAllowed = app?.isAllowed() ?: true

                Logger.debug("Logging connection: $protocol UID=$uid $destIP:$destPort (allowed=$isAllowed)")

                val log = Log(
                    time = System.currentTimeMillis(),
                    protocol = protocol,
                    packageID = uid,
                    sourceIP = sourceIP,
                    destinationAddress = null,
                    sourcePort = sourcePort,
                    destinationIP = destIP,
                    destinationPort = destPort,
                    packetStatus = if (isAllowed) FirewallResult.ACCEPT else FirewallResult.DROP
                )

                launch {
                    if (::logUseCases.isInitialized) {
                        val result = logUseCases.addLog.execute(log)
                        result.fold(
                            ifSuccess = {
                                // Mark connection as logged only after successful save
                                loggedConnections.add(connectionKey)
                                Logger.debug("Successfully logged connection: $connectionKey")
                            },
                            ifFailure = { error ->
                                Logger.error("Failed to log connection: ${error.message}")
                            }
                        )
                    } else {
                        Logger.warn("Cannot log connection: logUseCases not initialized yet")
                    }
                }
            }
        } catch (e: Exception) {
            Logger.debug("Error parsing connection line: ${e.message}")
        }
    }

    private fun parseAddress(address: String): Pair<String, String> {
        try {
            val (hexIP, hexPort) = address.split(":")
            val ip = hexToIP(hexIP)
            val port = hexPort.toInt(16).toString()
            return Pair(ip, port)
        } catch (e: Exception) {
            return Pair("0.0.0.0", "0")
        }
    }

    private fun hexToIP(hex: String): String {
        try {
            val bytes = hex.chunked(2).map { it.toInt(16).toByte() }.reversed()
            return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
        } catch (e: Exception) {
            return "0.0.0.0"
        }
    }

    // The OEM_DENY_3 chain cannot tell Wi-Fi from cellular, so an app is only
    // allowed when both toggles are on.
    private fun Application.isAllowed(): Boolean = internetAccess && cellularAccess

    private fun setAppNetworking(app: Application) {
        val allow = app.isAllowed()
        val svc = shizukuFirewallService
        if (svc != null && isServiceBound) {
            try {
                val success = svc.setPackageNetworking(app.packageID, allow)
                if (success) {
                    if (allow) deniedPackages.remove(app.packageID) else deniedPackages.add(app.packageID)
                    Logger.debug("ShizukuConnectionService: setPackageNetworking for ${app.packageID} = $allow succeeded")
                } else {
                    Logger.warn("ShizukuConnectionService: setPackageNetworking for ${app.packageID} = $allow failed")
                }
                // Keep the cached list in sync so logging reflects the new state.
                installedApplications = installedApplications?.map { if (it.packageID == app.packageID) app else it }
            } catch (e: Exception) {
                Logger.error("ShizukuConnectionService: exception setting package networking: ${e.message}")
            }
        } else {
            Logger.warn("ShizukuConnectionService: cannot set package networking — service not bound")
        }
    }

    inner class LocalBinder : Binder() {
        val service: ShizukuConnectionService
            get() = this@ShizukuConnectionService
    }
}
