package io.github.brennocm.palisade

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import io.github.brennocm.palisade.core.Flags
import io.github.brennocm.palisade.core.Mounts
import io.github.brennocm.palisade.core.PathState
import io.github.brennocm.palisade.core.Probe
import io.github.brennocm.palisade.core.ProbeResult
import io.github.brennocm.palisade.core.ProcMaps
import io.github.brennocm.palisade.core.ProcStatus
import io.github.brennocm.palisade.core.Report
import io.github.brennocm.palisade.core.RootArtifacts
import io.github.brennocm.palisade.core.SigningCert
import io.github.brennocm.palisade.core.Threads
import java.security.MessageDigest

/**
 * Runs every probe and returns what it saw. The result is evidence for the app's backend,
 * not a decision: send [Report.toJson] with a Play Integrity token and decide on the server.
 *
 * [inspect] reads several files under `/proc`; call it off the main thread.
 */
public class Palisade(private val config: PalisadeConfig = PalisadeConfig()) {

    public fun inspect(context: Context): Report {
        val results = linkedMapOf<Probe, ProbeResult>()
        results[Probe.SU_PATHS] = RootArtifacts.evaluateSuPaths(::pathState)
        results[Probe.BUILD_TAGS] = RootArtifacts.evaluateBuildTags(Build.TAGS)
        results[Probe.MOUNTS] = Mounts.evaluate(readText("/proc/self/mounts"))
        results[Probe.MAPS] = ProcMaps.evaluate(readText("/proc/self/maps"))
        results[Probe.THREADS] = Threads.evaluate(NativeProbes.threadNames()?.toList())
        results[Probe.TRACER] = ProcStatus.evaluate(readText("/proc/self/status"))
        results[Probe.DEBUGGABLE] =
            Flags.debuggable(context.applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0)
        results[Probe.JAVA_DEBUGGER] = Flags.javaDebugger(Debug.isDebuggerConnected())
        if (config.signingCertSha256.isNotEmpty()) {
            results[Probe.SIGNING_CERT] = SigningCert.evaluate(signingDigests(context), config.signingCertSha256)
        }
        return Report(results)
    }

    private fun readText(path: String): String? =
        NativeProbes.readFile(path, MAX_PROC_BYTES)?.toString(Charsets.UTF_8)

    private fun pathState(path: String): PathState = when (NativeProbes.access(path)) {
        0 -> PathState.PRESENT
        -ENOENT, -ENOTDIR -> PathState.ABSENT
        else -> PathState.UNKNOWN // EACCES and friends: SELinux hid it, so we cannot tell
    }

    @SuppressLint("PackageManagerGetSignatures") // pre-28 fallback only; 28+ uses signingInfo
    private fun signingDigests(context: Context): List<String>? = try {
        val pm = context.packageManager
        val certs: Array<Signature>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                .signingInfo?.apkContentsSigners
        } else {
            @Suppress("DEPRECATION")
            pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES).signatures
        }
        certs?.map { sha256Hex(it.toByteArray()) }
    } catch (_: PackageManager.NameNotFoundException) {
        null
    }

    private fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private companion object {
        const val MAX_PROC_BYTES = 4 * 1024 * 1024
        const val ENOENT = 2
        const val ENOTDIR = 20
    }
}
