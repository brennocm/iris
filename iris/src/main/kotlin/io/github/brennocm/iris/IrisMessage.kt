package io.github.brennocm.iris

import android.util.Base64
import java.security.MessageDigest

/**
 * What the app sends to its backend: the report bytes, a signature over them made with a fresh
 * Android Keystore key, and that key's attestation certificate chain (leaf first).
 *
 * The chain is produced by the device's secure hardware. Its leaf carries the server's
 * challenge, the app's package name and signing-certificate digests, and the verified boot
 * state, none of which a hook inside the app can change. The report itself is still written by
 * app code, so the signature proves freshness and origin, not that the report is truthful.
 *
 * When the device cannot produce an attestation, [attestationError] says why and
 * [signature]/[certificateChain] are empty; the backend should treat that as a signal.
 */
public class IrisMessage internal constructor(
    public val report: ByteArray,
    public val signature: ByteArray,
    public val certificateChain: List<ByteArray>,
    public val attestationError: String?,
) {
    /** Value to pass as `requestHash` to Play Integrity, so the verdict is bound to this report. */
    public fun requestHash(): String =
        MessageDigest.getInstance("SHA-256").digest(report).joinToString("") { "%02x".format(it) }

    public fun toJson(): String = buildString {
        append("{\"v\":").append(VERSION)
        append(",\"report\":\"").append(b64(report)).append('"')
        append(",\"signature\":\"").append(b64(signature)).append('"')
        append(",\"chain\":[")
        certificateChain.forEachIndexed { i, c ->
            if (i > 0) append(',')
            append('"').append(b64(c)).append('"')
        }
        append(']')
        if (attestationError != null) {
            // Exception messages are plain text; escape the characters JSON forbids.
            append(",\"attestation_error\":\"")
            attestationError.forEach { c ->
                when {
                    c == '"' || c == '\\' -> append('\\').append(c)
                    c < ' ' -> append("\\u%04x".format(c.code))
                    else -> append(c)
                }
            }
            append('"')
        }
        append('}')
    }

    private fun b64(bytes: ByteArray): String = Base64.encodeToString(bytes, Base64.NO_WRAP)

    public companion object {
        public const val VERSION: Int = 1
    }
}
