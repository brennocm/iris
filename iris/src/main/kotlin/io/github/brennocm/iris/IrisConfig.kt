package io.github.brennocm.iris

import io.github.brennocm.iris.core.SigningCert

/**
 * @property signingCertSha256 SHA-256 digests of the certificates allowed to sign the app, as
 * printed by `apksigner verify --print-certs` (colons optional). Empty skips the signing probe.
 * With Play App Signing, pin the app signing key from the Play Console, not the upload key.
 */
public class IrisConfig(signingCertSha256: Set<String> = emptySet()) {
    public val signingCertSha256: Set<String> = signingCertSha256.map(SigningCert::normalize).toSet()
}
