package verifier

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
	"github.com/brennocm/iris/server/internal/attestation/attestationtest"
	"github.com/brennocm/iris/server/internal/challenge"
	"github.com/brennocm/iris/server/internal/integrity"
)

const pkg = "com.example.app"

var digest = bytes.Repeat([]byte{0xab}, 32)

const cleanReport = `{"schema":1,"signals":[],"unavailable":[]}`

func defaults(c []byte) attestationtest.Options {
	return attestationtest.Options{
		Challenge: c, SecurityLevel: attestation.TrustedEnvironment, PackageName: pkg,
		SignatureDigest: digest, BootState: attestation.BootVerified, DeviceLocked: true,
	}
}

func sign(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()
	h := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

// verifyCase issues a challenge, builds a chain carrying it, trusts that chain's root and
// verifies a message signed by the attested key.
func verifyCase(t *testing.T, report string, opts func([]byte) attestationtest.Options, mutate func(*Config)) Decision {
	t.Helper()
	// The root key is random per chain, so build the chain, then trust its root.
	store := challenge.NewMemory(time.Minute, 100)
	c, _ := store.Issue(context.Background())
	chain := attestationtest.Build(opts(c))
	cfg := Config{PackageName: pkg, SigningCertDigests: [][]byte{digest}, Roots: []*x509.Certificate{chain.Root}, Challenges: store}
	if mutate != nil {
		mutate(&cfg)
	}
	v := New(cfg)
	v.SetStatusList(&attestation.StatusList{})
	m := &Message{V: 1, Report: []byte(report), Signature: sign(t, chain.LeafKey, []byte(report)), Chain: chain.DER}
	return v.Verify(context.Background(), m, "")
}

func expect(t *testing.T, d Decision, want Action, reason string) {
	t.Helper()
	if d.Action != want {
		t.Fatalf("action %s, want %s; reasons %q", d.Action, want, d.Reasons)
	}
	if reason == "" {
		return
	}
	for _, r := range d.Reasons {
		if strings.Contains(r, reason) {
			return
		}
	}
	t.Fatalf("no reason containing %q in %q", reason, d.Reasons)
}

func TestCleanAttestedReportIsAllowed(t *testing.T) {
	expect(t, verifyCase(t, cleanReport, defaults, nil), Allow, "Play Integrity not configured")
}

func TestChallengeCannotBeReplayed(t *testing.T) {
	store := challenge.NewMemory(time.Minute, 100)
	c, _ := store.Issue(context.Background())
	chain := attestationtest.Build(defaults(c))
	v := New(Config{PackageName: pkg, SigningCertDigests: [][]byte{digest}, Roots: []*x509.Certificate{chain.Root}, Challenges: store})
	v.SetStatusList(&attestation.StatusList{})
	m := &Message{V: 1, Report: []byte(cleanReport), Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
	expect(t, v.Verify(context.Background(), m, ""), Allow, "")
	expect(t, v.Verify(context.Background(), m, ""), Deny, "already used")
}

func TestUnissuedChallengeIsDenied(t *testing.T) {
	store := challenge.NewMemory(time.Minute, 100)
	chain := attestationtest.Build(defaults([]byte("made-up-challenge-by-the-client!")))
	v := New(Config{PackageName: pkg, Roots: []*x509.Certificate{chain.Root}, Challenges: store})
	v.SetStatusList(&attestation.StatusList{})
	m := &Message{V: 1, Report: []byte(cleanReport), Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
	expect(t, v.Verify(context.Background(), m, ""), Deny, "challenge unknown")
}

func TestAttestationFailuresAreDenied(t *testing.T) {
	cases := map[string]struct {
		opts   func([]byte) attestationtest.Options
		mutate func(*Config)
		reason string
	}{
		"other package": {func(c []byte) attestationtest.Options { o := defaults(c); o.PackageName = "com.evil"; return o }, nil, "attested app is not"},
		"repackaged": {func(c []byte) attestationtest.Options {
			o := defaults(c)
			o.SignatureDigest = bytes.Repeat([]byte{1}, 32)
			return o
		}, nil, "unknown certificate"},
		"software key": {func(c []byte) attestationtest.Options {
			o := defaults(c)
			o.SecurityLevel = attestation.Software
			return o
		}, nil, "software"},
		"no app id":      {func(c []byte) attestationtest.Options { o := defaults(c); o.OmitAppID = true; return o }, nil, "does not identify the app"},
		"untrusted root": {defaults, func(c *Config) { c.Roots = attestation.GoogleRoots() }, "trusted root"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			expect(t, verifyCase(t, cleanReport, tc.opts, tc.mutate), Deny, tc.reason)
		})
	}
}

func TestSoftwareAttestationCanBeAllowedForEmulators(t *testing.T) {
	soft := func(c []byte) attestationtest.Options {
		o := defaults(c)
		o.SecurityLevel = attestation.Software
		return o
	}
	d := verifyCase(t, cleanReport, soft, func(c *Config) { c.AllowSoftwareAttestation = true })
	expect(t, d, Allow, "software attestation accepted")
}

func TestForgedSignatureIsDenied(t *testing.T) {
	store := challenge.NewMemory(time.Minute, 100)
	c, _ := store.Issue(context.Background())
	chain := attestationtest.Build(defaults(c))
	v := New(Config{PackageName: pkg, Roots: []*x509.Certificate{chain.Root}, Challenges: store})
	v.SetStatusList(&attestation.StatusList{})
	// The signature covers a clean report, but a different report is sent.
	m := &Message{V: 1, Report: []byte(`{"schema":1,"signals":[],"unavailable":[],"x":1}`),
		Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
	expect(t, v.Verify(context.Background(), m, ""), Deny, "signature does not verify")
}

func TestRootOfTrustEscalatesToReview(t *testing.T) {
	unlocked := func(c []byte) attestationtest.Options {
		o := defaults(c)
		o.DeviceLocked, o.BootState = false, attestation.BootUnverified
		return o
	}
	d := verifyCase(t, cleanReport, unlocked, nil)
	expect(t, d, Review, "bootloader is unlocked")
	expect(t, d, Review, "verified boot state is unverified")
}

func TestSignalsDriveTheDecision(t *testing.T) {
	hook := `{"schema":1,"signals":[{"id":"HOOK-001","probe":"maps","evidence":"frida-agent-64.so"}],"unavailable":[]}`
	root := `{"schema":1,"signals":[{"id":"ROOT-001","probe":"su_paths","evidence":"/system/xbin/su"}],"unavailable":[]}`
	blind := `{"schema":1,"signals":[],"unavailable":[{"probe":"maps","reason":"could not read /proc/self/maps"}]}`
	expect(t, verifyCase(t, hook, defaults, nil), Deny, "HOOK-001")
	expect(t, verifyCase(t, root, defaults, nil), Review, "ROOT-001")
	emulator := `{"schema":1,"signals":[{"id":"ENV-001","probe":"emulator","evidence":"hardware=ranchu"}],"unavailable":[]}`
	expect(t, verifyCase(t, emulator, defaults, nil), Review, "ENV-001")
	inline := `{"schema":1,"signals":[{"id":"HOOK-004","probe":"inline_hooks","evidence":"openat: e9 93 b1 b3"}],"unavailable":[]}`
	expect(t, verifyCase(t, inline, defaults, nil), Deny, "HOOK-004")
	expect(t, verifyCase(t, blind, defaults, nil), Review, "probe maps did not run")
}

func TestUnattestedMessageIsReviewed(t *testing.T) {
	v := New(Config{PackageName: pkg, Challenges: challenge.NewMemory(time.Minute, 1)})
	m := &Message{V: 1, Report: []byte(cleanReport), AttestationError: "ProviderException: no keystore"}
	expect(t, v.Verify(context.Background(), m, ""), Review, "ProviderException")
}

func TestRevocationListMissingOrHit(t *testing.T) {
	store := challenge.NewMemory(time.Minute, 100)
	c, _ := store.Issue(context.Background())
	o := defaults(c)
	o.LeafSerial = 0xbad
	chain := attestationtest.Build(o)
	v := New(Config{PackageName: pkg, Roots: []*x509.Certificate{chain.Root}, Challenges: store})
	m := &Message{V: 1, Report: []byte(cleanReport), Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
	expect(t, v.Verify(context.Background(), m, ""), Review, "revocation list unavailable")

	c2, _ := store.Issue(context.Background())
	o.Challenge = c2
	chain = attestationtest.Build(o)
	v = New(Config{PackageName: pkg, Roots: []*x509.Certificate{chain.Root}, Challenges: store})
	var s attestation.StatusList
	_ = json.Unmarshal([]byte(`{"entries":{"bad":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}`), &s)
	v.SetStatusList(&s)
	m = &Message{V: 1, Report: []byte(cleanReport), Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
	expect(t, v.Verify(context.Background(), m, ""), Deny, "is REVOKED")
}

type fakeDecoder struct{ v *integrity.Verdict }

func (f fakeDecoder) Decode(context.Context, string) (*integrity.Verdict, error) { return f.v, nil }

func verdict(hash string, ts time.Time) *integrity.Verdict {
	v := &integrity.Verdict{}
	v.RequestDetails.RequestPackageName = pkg
	v.RequestDetails.RequestHash = hash
	v.RequestDetails.TimestampMillis = strconv.FormatInt(ts.UnixMilli(), 10)
	v.AppIntegrity.AppRecognitionVerdict = "PLAY_RECOGNIZED"
	v.DeviceIntegrity.DeviceRecognitionVerdict = []string{"MEETS_DEVICE_INTEGRITY"}
	return v
}

func TestPlayIntegrityIsBoundToTheReport(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	sum := sha256.Sum256([]byte(cleanReport))
	good := hex.EncodeToString(sum[:])
	run := func(v *integrity.Verdict, token string) Decision {
		store := challenge.NewMemory(time.Minute, 100)
		c, _ := store.Issue(context.Background())
		chain := attestationtest.Build(defaults(c))
		ver := New(Config{PackageName: pkg, Roots: []*x509.Certificate{chain.Root}, Challenges: store,
			Integrity: fakeDecoder{v}, Now: func() time.Time { return now }})
		ver.SetStatusList(&attestation.StatusList{})
		m := &Message{V: 1, Report: []byte(cleanReport), Signature: sign(t, chain.LeafKey, []byte(cleanReport)), Chain: chain.DER}
		return ver.Verify(context.Background(), m, token)
	}
	expect(t, run(verdict(good, now), "tok"), Allow, "")
	expect(t, run(verdict("00", now), "tok"), Deny, "not bound to this report")
	expect(t, run(verdict(good, now.Add(-time.Hour)), "tok"), Deny, "stale")
	bad := verdict(good, now)
	bad.DeviceIntegrity.DeviceRecognitionVerdict = nil
	expect(t, run(bad, "tok"), Deny, "device integrity")
	expect(t, run(verdict(good, now), ""), Review, "no Play Integrity token")
}

func TestGoogleDecoderRequestAndResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/"+pkg+":decodeIntegrityToken" {
			http.Error(w, r.URL.Path, http.StatusNotFound)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		fmt.Fprintf(w, `{"tokenPayloadExternal":{"requestDetails":{"requestHash":%q}}}`, body["integrityToken"])
	}))
	defer srv.Close()
	d := &integrity.GoogleDecoder{Client: srv.Client(), PackageName: pkg, Endpoint: srv.URL}
	v, err := d.Decode(context.Background(), "abc")
	if err != nil || v.RequestDetails.RequestHash != "abc" {
		t.Fatalf("%v %+v", err, v)
	}
}

func TestMessageJSONMatchesTheSDK(t *testing.T) {
	// IrisMessage.toJson() uses standard base64, which is what encoding/json expects for []byte.
	var m Message
	in := `{"v":1,"report":"eyJzY2hlbWEiOjF9","signature":"AQID","chain":["BAU="],"attestation_error":"x"}`
	if err := json.Unmarshal([]byte(in), &m); err != nil {
		t.Fatal(err)
	}
	if string(m.Report) != `{"schema":1}` || len(m.Signature) != 3 || len(m.Chain) != 1 || m.AttestationError != "x" {
		t.Fatalf("%+v", m)
	}
}

type brokenStore struct{ challenge.Store }

func (brokenStore) Consume(context.Context, []byte) (bool, error) {
	return false, fmt.Errorf("connection refused")
}

func TestChallengeStoreOutageIsNeverAllowed(t *testing.T) {
	d := verifyCase(t, cleanReport, defaults, func(c *Config) { c.Challenges = brokenStore{c.Challenges} })
	expect(t, d, Review, "challenge store unavailable")
}
