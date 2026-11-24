// Package attestationtest builds synthetic Android attestation chains for tests.
package attestationtest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
)

// Options controls what the leaf's attestation extension says.
type Options struct {
	Challenge       []byte
	SecurityLevel   attestation.SecurityLevel
	PackageName     string
	SignatureDigest []byte
	BootState       attestation.BootState
	DeviceLocked    bool
	OmitRootOfTrust bool
	OmitAppID       bool
	LeafSerial      int64
}

// Chain is a generated chain, leaf first.
type Chain struct {
	DER     [][]byte
	Root    *x509.Certificate
	LeafKey *ecdsa.PrivateKey
}

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func explicit(tag int, inner []byte) []byte {
	b, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
	if err != nil {
		panic(err)
	}
	return b
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

func sequence(elements ...[]byte) asn1.RawValue {
	var body []byte
	for _, e := range elements {
		body = append(body, e...)
	}
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: body}
}

// KeyDescription encodes the attestation extension described by o.
func KeyDescription(o Options) []byte {
	// An unrelated tag (purpose, [1] SET OF INTEGER) checks that unknown tags are skipped.
	purpose := explicit(1, must(asn1.Marshal([]int{2})))
	var sw, hw [][]byte
	sw = append(sw, purpose)
	if !o.OmitAppID {
		appID := must(asn1.Marshal(struct {
			Packages []struct {
				Name    []byte
				Version int64
			} `asn1:"set"`
			Digests [][]byte `asn1:"set"`
		}{
			Packages: []struct {
				Name    []byte
				Version int64
			}{{[]byte(o.PackageName), 1}},
			Digests: [][]byte{o.SignatureDigest},
		}))
		sw = append(sw, explicit(709, must(asn1.Marshal(appID))))
	}
	if !o.OmitRootOfTrust {
		rot := must(asn1.Marshal(struct {
			Key    []byte
			Locked bool
			State  asn1.Enumerated
			Hash   []byte
		}{make([]byte, 32), o.DeviceLocked, asn1.Enumerated(o.BootState), make([]byte, 32)}))
		hw = append(hw, explicit(704, rot))
	}
	return must(asn1.Marshal(struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeyMintVersion           int
		KeyMintSecurityLevel     asn1.Enumerated
		Challenge                []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		HardwareEnforced         asn1.RawValue
	}{300, asn1.Enumerated(o.SecurityLevel), 300, asn1.Enumerated(o.SecurityLevel), o.Challenge, []byte{},
		sequence(sw...), sequence(hw...)}))
}

// Build returns root -> intermediate -> leaf, with the leaf carrying KeyDescription(o).
func Build(o Options) Chain {
	rootKey, interKey, leafKey := mustKey(), mustKey(), mustKey()
	ca := func(serial int64, cn string) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Unix(0, 0),
			NotAfter:              time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
	}
	rootTmpl := ca(1, "test root")
	rootDER := must(x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey))
	root, _ := x509.ParseCertificate(rootDER)
	interTmpl := ca(2, "test intermediate")
	interDER := must(x509.CreateCertificate(rand.Reader, interTmpl, root, &interKey.PublicKey, rootKey))
	inter, _ := x509.ParseCertificate(interDER)

	serial := o.LeafSerial
	if serial == 0 {
		serial = 1
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Android Keystore Key"},
		NotBefore:    time.Unix(0, 0),
		NotAfter:     time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{
			Id: attestation.OIDKeyDescription, Value: KeyDescription(o),
		}},
	}
	leafDER := must(x509.CreateCertificate(rand.Reader, leafTmpl, inter, &leafKey.PublicKey, interKey))
	return Chain{DER: [][]byte{leafDER, interDER, rootDER}, Root: root, LeafKey: leafKey}
}
