package io.github.brennocm.palisade.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class RootAndSigningTest {
    @Test
    fun `reports only su paths that exist`() {
        val r = RootArtifacts.evaluateSuPaths { if (it == "/system/xbin/su") PathState.PRESENT else PathState.ABSENT }
        assertEquals(listOf("/system/xbin/su"), assertIs<ProbeResult.Completed>(r).signals.map { it.evidence })
    }

    @Test
    fun `su check is unavailable when no path could be checked`() {
        assertIs<ProbeResult.Unavailable>(RootArtifacts.evaluateSuPaths { PathState.UNKNOWN })
    }

    @Test
    fun `test-keys build tag`() {
        assertEquals(1, assertIs<ProbeResult.Completed>(RootArtifacts.evaluateBuildTags("dev-keys,test-keys")).signals.size)
        assertEquals(0, assertIs<ProbeResult.Completed>(RootArtifacts.evaluateBuildTags("release-keys")).signals.size)
        assertEquals(0, assertIs<ProbeResult.Completed>(RootArtifacts.evaluateBuildTags(null)).signals.size)
    }

    private val pin = "AB:CD:" + "01".repeat(30)

    @Test
    fun `normalizes keytool-style digests and rejects anything else`() {
        assertEquals("abcd" + "01".repeat(30), SigningCert.normalize(pin))
        assertFailsWith<IllegalArgumentException> { SigningCert.normalize("abcd") }
        assertFailsWith<IllegalArgumentException> { SigningCert.normalize("zz".repeat(32)) }
    }

    @Test
    fun `matching certificate is clean and a different one is a mismatch`() {
        val ok = SigningCert.evaluate(listOf("abcd" + "01".repeat(30)), setOf(pin))
        assertEquals(emptyList(), assertIs<ProbeResult.Completed>(ok).signals)
        val other = "ff".repeat(32)
        val bad = assertIs<ProbeResult.Completed>(SigningCert.evaluate(listOf(other), setOf(pin)))
        assertEquals(listOf(Signal(SignalId.SIGNING_CERT_MISMATCH, other)), bad.signals)
    }

    @Test
    fun `no certificates is unavailable`() {
        assertIs<ProbeResult.Unavailable>(SigningCert.evaluate(null, setOf(pin)))
        assertIs<ProbeResult.Unavailable>(SigningCert.evaluate(emptyList(), setOf(pin)))
    }
}
