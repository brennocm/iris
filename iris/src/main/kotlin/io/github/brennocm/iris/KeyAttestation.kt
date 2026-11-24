package io.github.brennocm.iris

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID

/**
 * Signs [payload] with a single-use EC P-256 key whose attestation embeds [challenge].
 * The key is deleted afterwards: one key per challenge, so a captured key cannot be reused.
 */
internal object KeyAttestation {
    private const val PROVIDER = "AndroidKeyStore"

    class Result(val signature: ByteArray, val chain: List<ByteArray>)

    fun sign(context: Context, payload: ByteArray, challenge: ByteArray): Result {
        val alias = "iris-" + UUID.randomUUID()
        val keyStore = KeyStore.getInstance(PROVIDER).apply { load(null) }
        try {
            generate(context, alias, challenge)
            val key = keyStore.getKey(alias, null) as? java.security.PrivateKey
                ?: error("keystore returned no private key")
            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(key)
                update(payload)
                sign()
            }
            val chain = keyStore.getCertificateChain(alias)?.map { it.encoded }
                ?: error("keystore returned no certificate chain")
            return Result(signature, chain)
        } finally {
            runCatching { keyStore.deleteEntry(alias) }
        }
    }

    private fun generate(context: Context, alias: String, challenge: ByteArray) {
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (strongBox) {
            try {
                generate(alias, challenge, strongBox = true)
                return
            } catch (_: StrongBoxUnavailableException) {
                // fall back to the TEE
            }
        }
        generate(alias, challenge, strongBox = false)
    }

    private fun generate(alias: String, challenge: ByteArray, strongBox: Boolean) {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .apply { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) setIsStrongBoxBacked(strongBox) }
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER).run {
            initialize(spec)
            generateKeyPair()
        }
    }
}
