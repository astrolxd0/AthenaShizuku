/*
 * Copyright (C) 2025-2026 Vexzure
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package com.kin.athena.service.shizuku

import com.kin.athena.core.logging.Logger
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Runs inside the Shizuku user-service process (shell or root uid) and drives
 * Android's FIREWALL_CHAIN_OEM_DENY_3 through `cmd connectivity`.
 *
 * The chain is a deny-list: enabling it blocks nothing until packages are
 * added with `set-package-networking-enabled false <pkg>`.
 *
 * Success is decided by the exit code of `cmd`, never by sniffing its output.
 * `cmd` returns 0 on success and a non-zero code for unknown subcommands,
 * bad arguments and any exception thrown by ConnectivityService.
 */
class ShizukuFirewallUserService : IShizukuFirewallService.Stub() {

    private data class CommandResult(val exitCode: Int, val output: String) {
        val ok: Boolean get() = exitCode == 0
    }

    override fun destroy() {
        Logger.info("ShizukuFirewallUserService: destroy() called")
        System.exit(0)
    }

    override fun enableFirewallChain(): Boolean {
        val result = run("cmd connectivity set-chain3-enabled true")
        Logger.info("ShizukuFirewallUserService: enableFirewallChain() -> exit ${result.exitCode} ${result.output}")
        return result.ok
    }

    override fun disableFirewallChain(): Boolean {
        val result = run("cmd connectivity set-chain3-enabled false")
        Logger.info("ShizukuFirewallUserService: disableFirewallChain() -> exit ${result.exitCode} ${result.output}")
        return result.ok
    }

    override fun isFirewallChainEnabled(): Boolean {
        val result = run("cmd connectivity get-chain3-enabled")
        Logger.debug("ShizukuFirewallUserService: isFirewallChainEnabled() -> exit ${result.exitCode} ${result.output}")
        return result.ok && result.output.contains("chain:enabled")
    }

    override fun setPackageNetworking(packageName: String, enabled: Boolean): Boolean {
        val result = run("cmd connectivity set-package-networking-enabled $enabled $packageName")
        if (result.ok) {
            Logger.debug("ShizukuFirewallUserService: setPackageNetworking($packageName, $enabled) ok: ${result.output}")
        } else {
            // Typical failures: package not found, or a system app sharing an appId < 10000,
            // which ConnectivityService refuses to put on the chain.
            Logger.warn("ShizukuFirewallUserService: setPackageNetworking($packageName, $enabled) failed (exit ${result.exitCode}): ${result.output}")
        }
        return result.ok
    }

    override fun setPackagesNetworking(packageNames: List<String>, enabled: Boolean): Int {
        var updated = 0
        packageNames.forEach { packageName ->
            if (setPackageNetworking(packageName, enabled)) updated++
        }
        Logger.info("ShizukuFirewallUserService: setPackagesNetworking(enabled=$enabled) updated $updated/${packageNames.size}")
        return updated
    }

    override fun getPackageNetworking(packageName: String): Boolean {
        val result = run("cmd connectivity get-package-networking-enabled $packageName")
        Logger.debug("ShizukuFirewallUserService: getPackageNetworking($packageName) -> exit ${result.exitCode} ${result.output}")
        // Output is "<pkg>:allow" or "<pkg>:deny". Default to allowed on failure.
        return !(result.ok && result.output.trim().endsWith(":deny"))
    }

    override fun executeCommand(command: String): String {
        return run(command).output
    }

    private fun run(command: String): CommandResult {
        Logger.debug("ShizukuFirewallUserService: run($command)")
        return try {
            val process = Runtime.getRuntime().exec(command)
            val output = StringBuilder()

            BufferedReader(InputStreamReader(process.inputStream)).use { reader ->
                reader.lineSequence().forEach { output.append(it).append('\n') }
            }
            BufferedReader(InputStreamReader(process.errorStream)).use { reader ->
                reader.lineSequence().forEach { output.append(it).append('\n') }
            }

            val exitCode = process.waitFor()
            CommandResult(exitCode, output.toString().trim())
        } catch (e: Exception) {
            Logger.error("ShizukuFirewallUserService: run($command) threw: ${e.message}")
            CommandResult(-1, e.message ?: "exception")
        }
    }
}
