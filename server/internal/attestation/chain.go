package attestation

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

//go:embed google_roots.pem
var googleRootsPEM []byte

// GoogleRoots returns Google's hardware attestation roots, as published at
// https://android.googleapis.com/attestation/root (fetched 2026-11-24). Older roots listed in
// the Android documentation reuse the same RSA key with other validity dates, and roots are
// matched by public key, so these two cover them.
func GoogleRoots() []*x509.Certificate {
	roots, err := ParsePEM(googleRootsPEM)
	if err != nil {
		panic("embedded roots: " + err.Error()) // covered by a unit test
	}
	return roots
}

// ParsePEM parses every CERTIFICATE block in data.
func ParsePEM(data []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("no certificates found")
	}
	return out, nil
}

var (
	ErrChainTooShort   = errors.New("attestation chain needs at least two certificates")
	ErrUntrustedRoot   = errors.New("attestation chain does not end at a trusted root")
	ErrExtensionMisuse = errors.New("attestation extension found outside the leaf")
	ErrNoExtension     = errors.New("leaf has no attestation extension")
)

// VerifyChain checks that each certificate is signed by the next and that the last one is
// a self-signed trusted root (matched by public key). Validity dates are not checked:
// attestation leaves carry placeholder dates on many devices, and Google's guidance is to rely
// on the revocation list instead. It returns the parsed key description of the leaf.
func VerifyChain(chain []*x509.Certificate, roots []*x509.Certificate) (*KeyDescription, error) {
	if len(chain) < 2 {
		return nil, ErrChainTooShort
	}
	for i := 0; i < len(chain)-1; i++ {
		child, parent := chain[i], chain[i+1]
		if err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature); err != nil {
			return nil, fmt.Errorf("certificate %d is not signed by certificate %d: %w", i, i+1, err)
		}
	}
	last := chain[len(chain)-1]
	if err := last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature); err != nil {
		return nil, fmt.Errorf("root is not self-signed: %w", err)
	}
	trusted := false
	for _, r := range roots {
		if bytes.Equal(last.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) {
			trusted = true
			break
		}
	}
	if !trusted {
		return nil, ErrUntrustedRoot
	}

	var ext []byte
	for i, c := range chain {
		for _, e := range c.Extensions {
			if !e.Id.Equal(OIDKeyDescription) {
				continue
			}
			if i != 0 {
				return nil, ErrExtensionMisuse
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return nil, ErrNoExtension
	}
	return ParseKeyDescription(ext)
}

// StatusList is Google's attestation revocation list
// (https://android.googleapis.com/attestation/status).
type StatusList struct {
	Entries map[string]struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	} `json:"entries"`
}

// Revoked returns the first certificate in chain listed as revoked or suspended.
func (s *StatusList) Revoked(chain []*x509.Certificate) (serial, status string, found bool) {
	for _, c := range chain {
		key := strings.ToLower(c.SerialNumber.Text(16))
		if e, ok := s.Entries[key]; ok {
			return key, e.Status, true
		}
	}
	return "", "", false
}
