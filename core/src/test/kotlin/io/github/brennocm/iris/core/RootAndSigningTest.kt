package io.github.brennocm.iris.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class RootAndSigningTest {
    @Test
    fun accessResultsMapToPathStates() {
        val noControl = { error("control must not run") }
        assertEquals(PathState.PRESENT, PathState.fromAccess(0, noControl))
        assertEquals(PathState.ABSENT, PathState.fromAccess(-2, noControl))
        assertEquals(PathState.ABSENT, PathState.fromAccess(-20, noControl))
        assertEquals(PathState.UNKNOWN, PathState.fromAccess(-5, noControl))
    }

    @Test
    fun eaccesMeansPresentOnlyWhenTheDirectoryWasSearched() {
        // su labelled su_exec: the file is denied but the directory answers ENOENT for others.
        assertEquals(PathState.PRESENT, PathState.fromAccess(-13) { -2 })
        // Directory itself unsearchable: EACCES says nothing about the file.
        assertEquals(PathState.UNKNOWN, PathState.fromAccess(-13) { -13 })
    }

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
