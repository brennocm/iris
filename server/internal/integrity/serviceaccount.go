package integrity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Scope required by the Play Integrity API.
const Scope = "https://www.googleapis.com/auth/playintegrity"

// ServiceAccount authenticates requests with a Google service account key (the JSON file
// downloaded from the Cloud console), using the OAuth 2.0 JWT bearer grant. Access tokens are
// cached until a minute before they expire.
//
// The account needs to be linked to the app in Play Console (App integrity > Play Integrity
// API > link a Cloud project). The key file is a credential: mount it as a secret, never bake
// it into an image.
type ServiceAccount struct {
	email    string
	key      *rsa.PrivateKey
	keyID    string
	tokenURI string
	scope    string
	client   *http.Client
	now      func() time.Time

	mu      sync.Mutex
	token   string
	expires time.Time
}

// ParseServiceAccount reads a service account JSON key.
func ParseServiceAccount(data []byte, scope string) (*ServiceAccount, error) {
	var f struct {
		Type         string `json:"type"`
		ClientEmail  string `json:"client_email"`
		PrivateKey   string `json:"private_key"`
		PrivateKeyID string `json:"private_key_id"`
		TokenURI     string `json:"token_uri"`
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("service account: %w", err)
	}
	if f.Type != "service_account" || f.ClientEmail == "" || f.PrivateKey == "" {
		return nil, errors.New("service account: not a service account key file")
	}
	block, _ := pem.Decode([]byte(f.PrivateKey))
	if block == nil {
		return nil, errors.New("service account: private_key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service account: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service account: private_key is not RSA")
	}
	if f.TokenURI == "" {
		f.TokenURI = "https://oauth2.googleapis.com/token"
	}
	if !strings.HasPrefix(f.TokenURI, "https://") && !strings.HasPrefix(f.TokenURI, "http://127.0.0.1") {
		return nil, errors.New("service account: token_uri must be https")
	}
	return &ServiceAccount{
		email: f.ClientEmail, key: key, keyID: f.PrivateKeyID, tokenURI: f.TokenURI, scope: scope,
		client: &http.Client{Timeout: 10 * time.Second}, now: time.Now,
	}, nil
}

// Client returns an HTTP client that adds a bearer token to every request.
func (s *ServiceAccount) Client() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &bearer{sa: s, base: http.DefaultTransport}}
}

// Token returns a valid access token, fetching a new one when needed.
func (s *ServiceAccount) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.expires.Add(-time.Minute)) {
		return s.token, nil
	}
	assertion, err := s.assertion()
	if err != nil {
		return "", err
	}
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {assertion},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oauth token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oauth token: HTTP %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		return "", errors.New("oauth token: unexpected response")
	}
	s.token = out.AccessToken
	s.expires = s.now().Add(time.Duration(out.ExpiresIn) * time.Second)
	return s.token, nil
}

// assertion builds the RS256-signed JWT the token endpoint exchanges for an access token.
func (s *ServiceAccount) assertion() (string, error) {
	now := s.now()
	header := map[string]string{"alg": "RS256", "typ": "JWT"}
	if s.keyID != "" {
		header["kid"] = s.keyID
	}
	claims := map[string]any{
		"iss": s.email, "scope": s.scope, "aud": s.tokenURI,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	signing := enc(header) + "." + enc(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

type bearer struct {
	sa   *ServiceAccount
	base http.RoundTripper
}

func (b *bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	tok, err := b.sa.Token(r.Context())
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+tok)
	return b.base.RoundTrip(r)
}
