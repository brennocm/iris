package io.github.brennocm.iris.core

/**
 * Compares the SHA-256 digests of the certificates the running APK was signed with against
 * the digests the developer pinned. A repackaged APK is signed with someone else's key.
 *
 * The digests come from the Android package manager, which runs in Java and can be hooked;
 * this probe catches repackaging, not an attacker who also instruments the process.
 */
public object SigningCert {
    private val HEX64 = Regex("[0-9a-f]{64}")

    /** Accepts `AB:CD:…` or plain hex, as printed by `apksigner` or `keytool`. */
    public fun normalize(digest: String): String {
        val hex = digest.replace(":", "").trim().lowercase()
        require(HEX64.matches(hex)) { "not a SHA-256 digest: $digest" }
        return hex
    }

    public fun evaluate(actual: List<String>?, pinned: Set<String>): ProbeResult {
        if (actual.isNullOrEmpty()) return ProbeResult.Unavailable("could not read signing certificates")
        val pins = pinned.map(::normalize).toSet()
        val seen = actual.map(::normalize)
        return ProbeResult.Completed(
            if (seen.any { it in pins }) {
                emptyList()
            } else {
                listOf(Signal.of(SignalId.SIGNING_CERT_MISMATCH, seen.joinToString(",")))
            },
        )
    }
}
