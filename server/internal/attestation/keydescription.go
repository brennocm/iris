// Package attestation verifies Android Keystore key attestation certificate chains and
// parses the attestation extension.
//
// Reference: https://source.android.com/docs/security/features/keystore/attestation
package attestation

import (
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDKeyDescription is the attestation extension carried by the leaf certificate.
var OIDKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// SecurityLevel is where the attested key lives.
type SecurityLevel int

const (
	Software           SecurityLevel = 0
	TrustedEnvironment SecurityLevel = 1
	StrongBox          SecurityLevel = 2
)

func (s SecurityLevel) String() string {
	switch s {
	case Software:
		return "software"
	case TrustedEnvironment:
		return "tee"
	case StrongBox:
		return "strongbox"
	}
	return fmt.Sprintf("unknown(%d)", int(s))
}

// BootState is the verified boot state reported by the bootloader.
type BootState int

const (
	BootVerified   BootState = 0
	BootSelfSigned BootState = 1
	BootUnverified BootState = 2
	BootFailed     BootState = 3
)

func (b BootState) String() string {
	names := [...]string{"verified", "self-signed", "unverified", "failed"}
	if b < 0 || int(b) >= len(names) {
		return fmt.Sprintf("unknown(%d)", int(b))
	}
	return names[b]
}

// RootOfTrust describes the device's boot chain.
type RootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState BootState
}

// Package is one entry of the attested application id.
type Package struct {
	Name    string
	Version int64
}

// ApplicationID identifies the app that generated the key, as seen by the platform.
type ApplicationID struct {
	Packages         []Package
	SignatureDigests [][]byte // SHA-256 of each signing certificate
}

// KeyDescription is the parsed attestation extension.
type KeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel SecurityLevel
	KeyMintVersion           int
	KeyMintSecurityLevel     SecurityLevel
	Challenge                []byte
	RootOfTrust              *RootOfTrust   // nil when absent
	ApplicationID            *ApplicationID // nil when absent
}

// Authorization list tags used here (KeyMint Tag numbers without the type bits).
const (
	tagRootOfTrust              = 704
	tagAttestationApplicationID = 709
)

type rawKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeyMintVersion           int
	KeyMintSecurityLevel     asn1.Enumerated
	Challenge                []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	HardwareEnforced         asn1.RawValue
}

type rawRootOfTrust struct {
	VerifiedBootKey   []byte
	DeviceLocked      bool
	VerifiedBootState asn1.Enumerated
	VerifiedBootHash  []byte `asn1:"optional"`
}

type rawPackage struct {
	Name    []byte
	Version int64
}

type rawApplicationID struct {
	Packages         []rawPackage `asn1:"set"`
	SignatureDigests [][]byte     `asn1:"set"`
}

// ParseKeyDescription parses the DER value of the attestation extension.
func ParseKeyDescription(der []byte) (*KeyDescription, error) {
	var raw rawKeyDescription
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("key description: %w", err)
	}
	kd := &KeyDescription{
		AttestationVersion:       raw.AttestationVersion,
		AttestationSecurityLevel: SecurityLevel(raw.AttestationSecurityLevel),
		KeyMintVersion:           raw.KeyMintVersion,
		KeyMintSecurityLevel:     SecurityLevel(raw.KeyMintSecurityLevel),
		Challenge:                raw.Challenge,
	}
	sw, err := parseAuthorizationList(raw.SoftwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("software-enforced list: %w", err)
	}
	hw, err := parseAuthorizationList(raw.HardwareEnforced)
	if err != nil {
		return nil, fmt.Errorf("hardware-enforced list: %w", err)
	}

	// The root of trust is only meaningful when the hardware enforces it.
	if v, ok := hw[tagRootOfTrust]; ok {
		if kd.RootOfTrust, err = parseRootOfTrust(v); err != nil {
			return nil, err
		}
	}
	// The application id is filled in by the platform, so it lives in the software list.
	for _, list := range []map[int][]byte{sw, hw} {
		if v, ok := list[tagAttestationApplicationID]; ok {
			if kd.ApplicationID, err = parseApplicationID(v); err != nil {
				return nil, err
			}
			break
		}
	}
	return kd, nil
}

// parseAuthorizationList returns the explicitly tagged elements of an AuthorizationList,
// keyed by tag number. Each value is the inner TLV. Unknown tags are kept and ignored.
func parseAuthorizationList(list asn1.RawValue) (map[int][]byte, error) {
	if list.Class != asn1.ClassUniversal || list.Tag != asn1.TagSequence {
		return nil, errors.New("not a SEQUENCE")
	}
	out := map[int][]byte{}
	rest := list.Bytes
	for len(rest) > 0 {
		var el asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &el); err != nil {
			return nil, err
		}
		if el.Class == asn1.ClassContextSpecific {
			out[el.Tag] = el.Bytes
		}
	}
	return out, nil
}

func parseRootOfTrust(der []byte) (*RootOfTrust, error) {
	var raw rawRootOfTrust
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return nil, fmt.Errorf("root of trust: %w", err)
	}
	return &RootOfTrust{
		VerifiedBootKey:   raw.VerifiedBootKey,
		DeviceLocked:      raw.DeviceLocked,
		VerifiedBootState: BootState(raw.VerifiedBootState),
	}, nil
}

func parseApplicationID(der []byte) (*ApplicationID, error) {
	var octets []byte
	if _, err := asn1.Unmarshal(der, &octets); err != nil {
		return nil, fmt.Errorf("application id wrapper: %w", err)
	}
	var raw rawApplicationID
	if _, err := asn1.Unmarshal(octets, &raw); err != nil {
		return nil, fmt.Errorf("application id: %w", err)
	}
	id := &ApplicationID{SignatureDigests: raw.SignatureDigests}
	for _, p := range raw.Packages {
		id.Packages = append(id.Packages, Package{Name: string(p.Name), Version: p.Version})
	}
	return id, nil
}
