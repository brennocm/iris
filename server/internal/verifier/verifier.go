// Package verifier turns an Iris message (and optionally a Play Integrity token) into a
// decision.
package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sync/atomic"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
	"github.com/brennocm/iris/server/internal/challenge"
	"github.com/brennocm/iris/server/internal/integrity"
	"github.com/brennocm/iris/server/internal/report"
)

// Action is what the backend should do with the request that carried the message.
type Action int

const (
	Allow Action = iota
	Review
	Deny
)

func (a Action) String() string { return [...]string{"allow", "review", "deny"}[a] }

func (a Action) MarshalJSON() ([]byte, error) { return json.Marshal(a.String()) }

// Decision is the verifier's answer. Reasons explain every escalation and every check that
// could not run.
type Decision struct {
	Action  Action   `json:"action"`
	Reasons []string `json:"reasons"`
}

func (d *Decision) add(a Action, reason string) {
	if a > d.Action {
		d.Action = a
	}
	d.Reasons = append(d.Reasons, reason)
}

// Message is the JSON envelope produced by IrisMessage.toJson().
type Message struct {
	V                int      `json:"v"`
	Report           []byte   `json:"report"`    // base64 in JSON
	Signature        []byte   `json:"signature"` // base64 in JSON
	Chain            [][]byte `json:"chain"`     // base64 DER, leaf first
	AttestationError string   `json:"attestation_error,omitempty"`
}

// Config describes the app this server protects.
type Config struct {
	PackageName string
	// SigningCertDigests are the SHA-256 digests of the app signing certificates. Empty skips
	// the check (not recommended outside tests).
	SigningCertDigests [][]byte
	Roots              []*x509.Certificate
	// AllowSoftwareAttestation accepts keys attested in software, as on emulators. Never in
	// production: a software attestation can be produced by anyone with the batch key.
	AllowSoftwareAttestation bool
	Challenges               *challenge.Store
	// Integrity is optional. When nil, Play Integrity is reported as not checked.
	Integrity       integrity.Decoder
	IntegrityMaxAge time.Duration
	Now             func() time.Time
}

// Verifier holds the configuration and the current revocation list.
type Verifier struct {
	cfg    Config
	status atomic.Pointer[attestation.StatusList]
}

func New(cfg Config) *Verifier {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.IntegrityMaxAge == 0 {
		cfg.IntegrityMaxAge = 5 * time.Minute
	}
	return &Verifier{cfg: cfg}
}

// SetStatusList replaces the revocation list (safe for concurrent use).
func (v *Verifier) SetStatusList(s *attestation.StatusList) { v.status.Store(s) }

// Verify evaluates one message. integrityToken may be empty.
func (v *Verifier) Verify(ctx context.Context, m *Message, integrityToken string) Decision {
	d := Decision{Reasons: []string{}}
	if m.V != 1 {
		d.add(Deny, fmt.Sprintf("unsupported message version %d", m.V))
		return d
	}
	rep, err := report.Parse(m.Report)
	if err != nil {
		d.add(Deny, err.Error())
		return d
	}

	v.checkAttestation(&d, m)
	v.checkSignals(&d, rep)
	v.checkIntegrity(ctx, &d, m, integrityToken)
	return d
}

func (v *Verifier) checkAttestation(d *Decision, m *Message) {
	if len(m.Chain) == 0 {
		reason := "attestation unavailable on the device"
		if m.AttestationError != "" {
			reason += ": " + m.AttestationError
		}
		// Without a chain the challenge cannot be checked, so the report may be replayed.
		d.add(Review, reason)
		return
	}
	chain := make([]*x509.Certificate, 0, len(m.Chain))
	for i, der := range m.Chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			d.add(Deny, fmt.Sprintf("certificate %d does not parse: %v", i, err))
			return
		}
		chain = append(chain, c)
	}
	kd, err := attestation.VerifyChain(chain, v.cfg.Roots)
	if err != nil {
		d.add(Deny, "attestation: "+err.Error())
		return
	}
	if s := v.status.Load(); s == nil {
		d.add(Review, "attestation revocation list unavailable")
	} else if serial, status, found := s.Revoked(chain); found {
		d.add(Deny, fmt.Sprintf("attestation certificate %s is %s", serial, status))
		return
	}
	if !v.cfg.Challenges.Consume(kd.Challenge) {
		d.add(Deny, "challenge unknown, expired or already used")
		return
	}
	if kd.AttestationSecurityLevel == attestation.Software {
		if !v.cfg.AllowSoftwareAttestation {
			d.add(Deny, "key attested in software, not in secure hardware")
			return
		}
		d.Reasons = append(d.Reasons, "software attestation accepted by configuration")
	}

	// The signature binds the report to the attested (and therefore fresh) key.
	pub, ok := chain[0].PublicKey.(*ecdsa.PublicKey)
	digest := sha256.Sum256(m.Report)
	if !ok || !ecdsa.VerifyASN1(pub, digest[:], m.Signature) {
		d.add(Deny, "report signature does not verify with the attested key")
		return
	}

	v.checkApplication(d, kd.ApplicationID)
	v.checkRootOfTrust(d, kd)
}

func (v *Verifier) checkApplication(d *Decision, app *attestation.ApplicationID) {
	if app == nil {
		d.add(Deny, "attestation does not identify the app")
		return
	}
	if !slices.ContainsFunc(app.Packages, func(p attestation.Package) bool { return p.Name == v.cfg.PackageName }) {
		d.add(Deny, "attested app is not "+v.cfg.PackageName)
		return
	}
	if len(v.cfg.SigningCertDigests) == 0 {
		return
	}
	for _, got := range app.SignatureDigests {
		for _, want := range v.cfg.SigningCertDigests {
			if bytes.Equal(got, want) {
				return
			}
		}
	}
	d.add(Deny, "app is signed with an unknown certificate (repackaged?)")
}

func (v *Verifier) checkRootOfTrust(d *Decision, kd *attestation.KeyDescription) {
	rot := kd.RootOfTrust
	if rot == nil {
		d.add(Review, "attestation has no hardware root of trust")
		return
	}
	if rot.VerifiedBootState != attestation.BootVerified {
		d.add(Review, "verified boot state is "+rot.VerifiedBootState.String())
	}
	if !rot.DeviceLocked {
		d.add(Review, "bootloader is unlocked")
	}
}

func (v *Verifier) checkSignals(d *Decision, r *report.Report) {
	for _, s := range r.Signals {
		reason := fmt.Sprintf("%s (%s): %s", s.ID, s.Probe, s.Evidence)
		switch s.Category() {
		case "HOOK", "TAMPER":
			d.add(Deny, reason)
		default: // ROOT, DEBUG and anything newer than this server
			d.add(Review, reason)
		}
	}
	for _, u := range r.Unavailable {
		d.add(Review, fmt.Sprintf("probe %s did not run: %s", u.Probe, u.Reason))
	}
}

func (v *Verifier) checkIntegrity(ctx context.Context, d *Decision, m *Message, token string) {
	if v.cfg.Integrity == nil {
		d.Reasons = append(d.Reasons, "Play Integrity not configured")
		return
	}
	if token == "" {
		d.add(Review, "no Play Integrity token")
		return
	}
	verdict, err := v.cfg.Integrity.Decode(ctx, token)
	if err != nil {
		d.add(Review, "Play Integrity unavailable: "+err.Error())
		return
	}
	sum := sha256.Sum256(m.Report)
	for _, p := range verdict.Problems(v.cfg.PackageName, hex.EncodeToString(sum[:]), v.cfg.Now(), v.cfg.IntegrityMaxAge) {
		d.add(Deny, p)
	}
}
