package attestation_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
	"github.com/brennocm/iris/server/internal/attestation/attestationtest"
)

func parse(t *testing.T, ders [][]byte) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, d := range ders {
		c, err := x509.ParseCertificate(d)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func opts() attestationtest.Options {
	return attestationtest.Options{
		Challenge:       []byte("0123456789abcdef0123456789abcdef"),
		SecurityLevel:   attestation.TrustedEnvironment,
		PackageName:     "com.example.app",
		SignatureDigest: bytes.Repeat([]byte{0xab}, 32),
		BootState:       attestation.BootVerified,
		DeviceLocked:    true,
	}
}

func TestGoogleRootsParse(t *testing.T) {
	if n := len(attestation.GoogleRoots()); n != 2 {
		t.Fatalf("expected 2 embedded roots, got %d", n)
	}
}

func TestVerifyChainParsesTheLeafExtension(t *testing.T) {
	c := attestationtest.Build(opts())
	kd, err := attestation.VerifyChain(parse(t, c.DER), []*x509.Certificate{c.Root})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kd.Challenge, opts().Challenge) || kd.AttestationSecurityLevel != attestation.TrustedEnvironment {
		t.Fatalf("unexpected key description: %+v", kd)
	}
	if kd.RootOfTrust == nil || !kd.RootOfTrust.DeviceLocked || kd.RootOfTrust.VerifiedBootState != attestation.BootVerified {
		t.Fatalf("root of trust: %+v", kd.RootOfTrust)
	}
	if kd.ApplicationID == nil || kd.ApplicationID.Packages[0].Name != "com.example.app" ||
		!bytes.Equal(kd.ApplicationID.SignatureDigests[0], opts().SignatureDigest) {
		t.Fatalf("application id: %+v", kd.ApplicationID)
	}
}

func TestVerifyChainRejects(t *testing.T) {
	c := attestationtest.Build(opts())
	other := attestationtest.Build(opts())
	chain := parse(t, c.DER)

	if _, err := attestation.VerifyChain(chain, []*x509.Certificate{other.Root}); !errors.Is(err, attestation.ErrUntrustedRoot) {
		t.Errorf("foreign root: %v", err)
	}
	if _, err := attestation.VerifyChain(chain[:1], []*x509.Certificate{c.Root}); !errors.Is(err, attestation.ErrChainTooShort) {
		t.Errorf("short chain: %v", err)
	}
	// Leaf from one chain spliced onto another chain's intermediate.
	spliced := []*x509.Certificate{parse(t, other.DER)[0], chain[1], chain[2]}
	if _, err := attestation.VerifyChain(spliced, []*x509.Certificate{c.Root}); err == nil {
		t.Error("spliced chain accepted")
	}
}

// An app can sign arbitrary bytes with its own attested key, including a certificate. A leaf
// forged that way (claiming a locked device, any challenge) chains correctly to the root, so
// the only thing that stops it is the rule that the attestation extension appears on the leaf
// alone: the genuine attested key's certificate, now second in the chain, carries one too.
func TestLeafForgedWithAnAttestedKeyIsRejected(t *testing.T) {
	genuine := attestationtest.Build(opts())
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99),
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC),
		ExtraExtensions: []pkix.Extension{{
			Id: attestation.OIDKeyDescription, Value: attestationtest.KeyDescription(opts()),
		}},
	}
	attacker, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	genuineLeaf := parse(t, genuine.DER)[0]
	forged, err := x509.CreateCertificate(rand.Reader, tmpl, genuineLeaf, &attacker.PublicKey, genuine.LeafKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := parse(t, append([][]byte{forged}, genuine.DER...))
	if _, err := attestation.VerifyChain(chain, []*x509.Certificate{genuine.Root}); !errors.Is(err, attestation.ErrExtensionMisuse) {
		t.Fatalf("forged leaf: %v", err)
	}
}

func TestBootStateStringIsTotal(t *testing.T) {
	if got := attestation.BootState(-1).String(); got != "unknown(-1)" {
		t.Fatal(got)
	}
	if got := attestation.BootState(9).String(); got != "unknown(9)" {
		t.Fatal(got)
	}
}

func TestMissingOptionalFields(t *testing.T) {
	o := opts()
	o.OmitRootOfTrust, o.OmitAppID = true, true
	kd, err := attestation.ParseKeyDescription(attestationtest.KeyDescription(o))
	if err != nil {
		t.Fatal(err)
	}
	if kd.RootOfTrust != nil || kd.ApplicationID != nil {
		t.Fatalf("expected absent fields: %+v", kd)
	}
}

func TestRevocation(t *testing.T) {
	o := opts()
	o.LeafSerial = 0xdead
	chain := parse(t, attestationtest.Build(o).DER)
	s := &attestation.StatusList{}
	if _, _, found := s.Revoked(chain); found {
		t.Fatal("empty list revoked something")
	}
	s.Entries = map[string]struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}{"dead": {Status: "REVOKED", Reason: "KEY_COMPROMISE"}}
	if serial, status, found := s.Revoked(chain); !found || serial != "dead" || status != "REVOKED" {
		t.Fatalf("got %s %s %v", serial, status, found)
	}
}
