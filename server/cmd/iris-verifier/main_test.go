package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brennocm/iris/server/internal/challenge"
	"github.com/brennocm/iris/server/internal/verifier"
)

func server(t *testing.T) *httptest.Server {
	t.Helper()
	store := challenge.NewStore(time.Minute, 10)
	v := verifier.New(verifier.Config{PackageName: "com.example.app", Challenges: store})
	srv := httptest.NewServer(routes(slog.New(slog.NewTextHandler(io.Discard, nil)), v, store))
	t.Cleanup(srv.Close)
	return srv
}

func TestRoutes(t *testing.T) {
	srv := server(t)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("healthz: %v %v", err, resp)
	}

	resp, err = http.Post(srv.URL+"/v1/challenge", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var ch struct {
		Challenge []byte `json:"challenge"`
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil || len(ch.Challenge) != challenge.Size || ch.ExpiresIn != 60 {
		t.Fatalf("challenge: %v %+v", err, ch)
	}

	// No attestation: the report is still evaluated and the missing check is reported.
	body := `{"message":{"v":1,"report":"eyJzY2hlbWEiOjEsInNpZ25hbHMiOltdLCJ1bmF2YWlsYWJsZSI6W119","signature":"","chain":[],"attestation_error":"x"}}`
	resp, err = http.Post(srv.URL+"/v1/verify", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	var d struct {
		Action  string   `json:"action"`
		Reasons []string `json:"reasons"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil || d.Action != "review" {
		t.Fatalf("verify: %v %+v", err, d)
	}
}

func TestVerifyRejectsMalformedAndOversizedBodies(t *testing.T) {
	srv := server(t)
	for name, body := range map[string]string{
		"not json":   "nope",
		"no message": `{"integrity_token":"x"}`,
		"too large":  `{"message":{"report":"` + strings.Repeat("A", 70<<10) + `"}}`,
	} {
		resp, err := http.Post(srv.URL+"/v1/verify", "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s: status %d", name, resp.StatusCode)
		}
	}
	if resp, _ := http.Get(srv.URL + "/v1/verify"); resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET /v1/verify: status %d", resp.StatusCode)
	}
}
