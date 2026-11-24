package io.github.brennocm.iris

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import io.github.brennocm.iris.core.Category
import io.github.brennocm.iris.core.Probe
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayInputStream
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Runs on any emulator or device without instrumentation attached. Root signals depend on the
 * image, so they are not asserted here; docs/scenarios.md covers rooted and Frida runs.
 */
@RunWith(AndroidJUnit4::class)
class IrisDeviceTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Test
    fun nativeProbesRunOnTheDevice() {
        val report = Iris().inspect(context)
        for (probe in listOf(
            Probe.MAPS,
            Probe.MOUNTS,
            Probe.THREADS,
            Probe.TRACER,
            Probe.SU_PATHS,
            Probe.INLINE_HOOKS,
            Probe.ART_HOOKS,
        )) {
            assertNull("$probe should run, got ${report.unavailable[probe]}", report.unavailable[probe])
        }
    }

    @Test
    fun noHookOrTracerSignalsWithoutInstrumentation() {
        val signals = Iris().inspect(context).signals
        assertEquals(emptyList<Any>(), signals.filter { it.id.category == Category.HOOK })
        assertTrue(signals.none { it.id.code == "DEBUG-001" })
    }

    @Test
    fun signedMessageVerifiesWithTheAttestedKey() {
        val challenge = ByteArray(32).also { SecureRandom().nextBytes(it) }
        val message = Iris().inspectAndSign(context, challenge)
        assertNull(message.attestationError)
        assertTrue("chain too short: ${message.certificateChain.size}", message.certificateChain.size >= 2)

        val factory = CertificateFactory.getInstance("X.509")
        val chain = message.certificateChain.map {
            factory.generateCertificate(ByteArrayInputStream(it)) as X509Certificate
        }
        val ok = Signature.getInstance("SHA256withECDSA").run {
            initVerify(chain.first().publicKey)
            update(message.report)
            verify(message.signature)
        }
        assertTrue("signature does not verify with the leaf key", ok)
        // Each certificate is signed by the next one.
        chain.zipWithNext().forEach { (child, parent) -> child.verify(parent.publicKey) }
        // The attestation extension is present on the leaf.
        assertTrue(chain.first().getExtensionValue("1.3.6.1.4.1.11129.2.1.17") != null)
    }
}
