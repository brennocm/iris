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
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func keyFile(t *testing.T, key *rsa.PrivateKey, tokenURI string) []byte {
	t.Helper()
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	b, _ := json.Marshal(map[string]string{
		"type": "service_account", "client_email": "verifier@example.iam.gserviceaccount.com",
		"private_key": pemKey, "private_key_id": "k1", "token_uri": tokenURI,
	})
	return b
}

func TestServiceAccountTokenFlow(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	var tokenCalls, apiCalls atomic.Int32
	var tokenURL string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenCalls.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
				http.Error(w, "grant", 400)
				return
			}
			parts := strings.Split(r.Form.Get("assertion"), ".")
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
				http.Error(w, "signature", 401)
				return
			}
			raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var c map[string]any
			_ = json.Unmarshal(raw, &c)
			if c["scope"] != Scope || c["aud"] != tokenURL || c["iss"] != "verifier@example.iam.gserviceaccount.com" {
				http.Error(w, fmt.Sprint(c), 400)
				return
			}
			fmt.Fprint(w, `{"access_token":"ya29.test","expires_in":3600,"token_type":"Bearer"}`)
		case "/v1/com.example.app:decodeIntegrityToken":
			apiCalls.Add(1)
			if r.Header.Get("Authorization") != "Bearer ya29.test" {
				http.Error(w, "auth", 401)
				return
			}
			fmt.Fprint(w, `{"tokenPayloadExternal":{"requestDetails":{"requestPackageName":"com.example.app"}}}`)
		}
	}))
	defer srv.Close()
	tokenURL = srv.URL + "/token"

	// Test servers are http://127.0.0.1, which the parser allows for this purpose only.
	sa, err := ParseServiceAccount(keyFile(t, key, tokenURL), Scope)
	if err != nil {
		t.Fatal(err)
	}
	d := &GoogleDecoder{Client: sa.Client(), PackageName: "com.example.app", Endpoint: srv.URL}
	for i := 0; i < 3; i++ {
		v, err := d.Decode(context.Background(), "tok")
		if err != nil || v.RequestDetails.RequestPackageName != "com.example.app" {
			t.Fatalf("decode %d: %v %+v", i, err, v)
		}
	}
	if tokenCalls.Load() != 1 || apiCalls.Load() != 3 {
		t.Fatalf("token fetched %d times for %d API calls; want 1 and 3", tokenCalls.Load(), apiCalls.Load())
	}

	// After expiry (minus the one-minute margin) a new token is fetched.
	now := time.Now().Add(59*time.Minute + time.Second)
	sa.now = func() time.Time { return now }
	if _, err := sa.Token(context.Background()); err != nil || tokenCalls.Load() != 2 {
		t.Fatalf("refresh: %v, %d token calls", err, tokenCalls.Load())
	}
}

func TestParseServiceAccountRejects(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, data := range map[string][]byte{
		"not json":   []byte("x"),
		"wrong type": []byte(`{"type":"authorized_user"}`),
		"plain http": keyFile(t, key, "http://evil.example/token"),
		"bad pem":    []byte(`{"type":"service_account","client_email":"a","private_key":"nope"}`),
	} {
		if _, err := ParseServiceAccount(data, Scope); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
