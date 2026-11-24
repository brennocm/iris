package io.github.brennocm.iris

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import io.github.brennocm.iris.core.Flags
import io.github.brennocm.iris.core.Mounts
import io.github.brennocm.iris.core.PathState
import io.github.brennocm.iris.core.Probe
import io.github.brennocm.iris.core.ProbeResult
import io.github.brennocm.iris.core.ProcMaps
import io.github.brennocm.iris.core.ProcStatus
import io.github.brennocm.iris.core.Report
import io.github.brennocm.iris.core.RootArtifacts
import io.github.brennocm.iris.core.SigningCert
import io.github.brennocm.iris.core.Threads
import java.security.MessageDigest
import java.util.UUID

/**
 * Runs every probe and returns what it saw. The result is evidence for the app's backend,
 * not a decision: send [Report.toJson] with a Play Integrity token and decide on the server.
 *
 * [inspect] reads several files under `/proc`; call it off the main thread.
 */
public class Iris(private val config: IrisConfig = IrisConfig()) {

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

    /**
     * Runs [inspect] and signs the report with a fresh hardware-backed key attested with
     * [challenge], a single-use value obtained from the backend (16 to 128 bytes).
     *
     * Key generation can take a second or more, especially with StrongBox. Call it off the
     * main thread.
     */
    public fun inspectAndSign(context: Context, challenge: ByteArray): IrisMessage {
        require(challenge.size in 16..128) { "challenge must be 16 to 128 bytes" }
        val report = inspect(context).toJson().toByteArray(Charsets.UTF_8)
        return try {
            val signed = KeyAttestation.sign(context, report, challenge)
            IrisMessage(report, signed.signature, signed.chain, attestationError = null)
        } catch (e: java.security.GeneralSecurityException) {
            unattested(report, e)
        } catch (e: java.security.ProviderException) {
            unattested(report, e)
        } catch (e: IllegalStateException) {
            unattested(report, e)
        }
    }

    private fun unattested(report: ByteArray, e: Exception) =
        IrisMessage(report, ByteArray(0), emptyList(), "${e.javaClass.simpleName}: ${e.message}".take(200))

    private fun readText(path: String): String? =
        NativeProbes.readFile(path, MAX_PROC_BYTES)?.toString(Charsets.UTF_8)

    private fun pathState(path: String): PathState = PathState.fromAccess(NativeProbes.access(path)) {
        NativeProbes.access(path.substringBeforeLast('/') + "/.iris-control-" + UUID.randomUUID())
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
    }
}
