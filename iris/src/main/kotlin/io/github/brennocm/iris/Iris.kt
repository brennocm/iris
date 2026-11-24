package io.github.brennocm.iris

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import android.os.Debug
import android.os.Looper
import io.github.brennocm.iris.core.ArtHooks
import io.github.brennocm.iris.core.Emulator
import io.github.brennocm.iris.core.Flags
import io.github.brennocm.iris.core.FridaPorts
import io.github.brennocm.iris.core.InlineHooks
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
import java.io.File
import java.lang.reflect.Modifier
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
        if (NativeProbes.load()) {
            results[Probe.SU_PATHS] = RootArtifacts.evaluateSuPaths(::pathState)
            results[Probe.MOUNTS] = procProbe("/proc/self/mounts", Mounts::evaluate)
            results[Probe.MAPS] = procProbe("/proc/self/maps", ProcMaps::evaluate)
            results[Probe.THREADS] = Threads.evaluate(NativeProbes.threadNames()?.toList())
            results[Probe.TRACER] = procProbe("/proc/self/status", ProcStatus::evaluate)
            results[Probe.FRIDA_PORT] = FridaPorts.evaluate(
                mapOf("tcp" to procText("/proc/net/tcp"), "tcp6" to procText("/proc/net/tcp6")),
                NativeProbes::connectLoopback,
            )
            results[Probe.INLINE_HOOKS] = InlineHooks.evaluate(
                procText("/proc/self/maps"),
                { NativeProbes.readFile(it, MAX_LIB_BYTES) },
                NativeProbes::readMemory,
            )
        } else {
            // libiris.so missing or not loadable (unsupported ABI, stripped or tampered APK):
            // report the native probes as blind instead of letting the error crash the app.
            for (p in NATIVE_PROBES) {
                results[p] = ProbeResult.Unavailable("native library unavailable")
            }
        }
        results[Probe.BUILD_TAGS] = RootArtifacts.evaluateBuildTags(Build.TAGS)
        val stat: (String) -> PathState = if (NativeProbes.load()) ::pathState else { _ -> PathState.UNKNOWN }
        results[Probe.EMULATOR] = Emulator.evaluate(
            Emulator.BuildInfo(
                fingerprint = Build.FINGERPRINT.orEmpty(),
                model = Build.MODEL.orEmpty(),
                manufacturer = Build.MANUFACTURER.orEmpty(),
                brand = Build.BRAND.orEmpty(),
                device = Build.DEVICE.orEmpty(),
                product = Build.PRODUCT.orEmpty(),
                hardware = Build.HARDWARE.orEmpty(),
            ),
            stat,
        )
        results[Probe.ART_HOOKS] =
            ArtHooks.evaluate(nativeJavaMethods(context), stackClasses(), loadableFrameworkClasses())
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
        val signed = try {
            KeyAttestation.sign(context, report, challenge)
        } catch (e: Exception) {
            // Keystore implementations differ by vendor and throw undocumented exceptions
            // (ProviderException, IOException from load(), ...). Any of them must degrade to an
            // unattested message, never crash the host app.
            return unattested(report, "${e.javaClass.simpleName}: ${e.message}")
        }
        // Devices without key attestation return the key's self-signed certificate alone.
        if (signed.chain.size < 2) return unattested(report, "device does not support key attestation")
        return IrisMessage(report, signed.signature, signed.chain, attestationError = null)
    }

    private fun unattested(report: ByteArray, reason: String) =
        IrisMessage(report, ByteArray(0), emptyList(), reason.take(200))

    /**
     * Reads a /proc file and evaluates it. A file larger than [MAX_PROC_BYTES] is evaluated on
     * its first part: signals found there are kept, but a clean result becomes unavailable,
     * because padding the file (mapping thousands of regions, say) must not hide what follows.
     */
    private fun procProbe(path: String, evaluate: (String?) -> ProbeResult): ProbeResult {
        val bytes = NativeProbes.readFile(path, MAX_PROC_BYTES + 1)
        if (bytes == null || bytes.size <= MAX_PROC_BYTES) return evaluate(bytes?.toString(Charsets.UTF_8))
        val partial = evaluate(bytes.copyOf(MAX_PROC_BYTES).toString(Charsets.UTF_8))
        return if (partial is ProbeResult.Completed && partial.signals.isNotEmpty()) {
            partial
        } else {
            ProbeResult.Unavailable("$path is larger than $MAX_PROC_BYTES bytes")
        }
    }

    private fun procText(path: String): String? = NativeProbes.readFile(path, MAX_PROC_BYTES)?.toString(Charsets.UTF_8)

    /**
     * Methods compiled from Java whose modifiers now say native: the trace Frida's Java bridge
     * leaves when it replaces a method. Checked on this SDK's own probe classes (none of which
     * declares a native method) and on framework methods that bypass scripts commonly hook.
     */
    private fun nativeJavaMethods(context: Context): List<String>? = try {
        val own = listOf(
            Iris::class.java, IrisMessage::class.java, KeyAttestation::class.java, Report::class.java,
            Flags::class.java, ProcMaps::class.java, ProcStatus::class.java, Mounts::class.java,
            Threads::class.java, RootArtifacts::class.java, SigningCert::class.java, Emulator::class.java,
            FridaPorts::class.java, InlineHooks::class.java, ArtHooks::class.java, PathState.Companion::class.java,
        ).flatMap { it.declaredMethods.toList() }
        val framework = listOf(
            { File::class.java.getMethod("exists") },
            { Runtime::class.java.getMethod("exec", String::class.java) },
            { System::class.java.getMethod("getProperty", String::class.java) },
            { Class::class.java.getMethod("forName", String::class.java) },
            {
                context.packageManager.javaClass
                    .getMethod("getPackageInfo", String::class.java, Int::class.javaPrimitiveType)
            },
        ).mapNotNull { lookup -> runCatching(lookup).getOrNull() }
        (own + framework).filter { Modifier.isNative(it.modifiers) }.map { "${it.declaringClass.name}.${it.name}" }
    } catch (_: SecurityException) {
        null
    } catch (_: LinkageError) {
        null
    }

    private fun stackClasses(): List<String> {
        val main = runCatching { Looper.getMainLooper().thread.stackTrace }.getOrNull().orEmpty()
        return (Thread.currentThread().stackTrace + main).map { it.className }
    }

    private fun loadableFrameworkClasses(): List<String> = FRAMEWORK_CLASSES.filter { name ->
        listOf(ClassLoader.getSystemClassLoader(), Iris::class.java.classLoader).any { loader ->
            runCatching { Class.forName(name, false, loader) }.isSuccess
        }
    }

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
        const val MAX_LIB_BYTES = 16 * 1024 * 1024
        val NATIVE_PROBES = listOf(
            Probe.SU_PATHS,
            Probe.MOUNTS,
            Probe.MAPS,
            Probe.THREADS,
            Probe.TRACER,
            Probe.FRIDA_PORT,
            Probe.INLINE_HOOKS,
        )
        val FRAMEWORK_CLASSES = listOf(
            "de.robv.android.xposed.XposedBridge",
            "de.robv.android.xposed.XposedHelpers",
            "org.lsposed.lspd.core.Main",
        )
    }
}
