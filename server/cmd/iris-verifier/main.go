// Command iris-verifier is a reference backend for the Iris SDK: it issues attestation
// challenges and turns Iris messages into allow / review / deny decisions.
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
	"github.com/brennocm/iris/server/internal/challenge"
	"github.com/brennocm/iris/server/internal/verifier"
)

const statusURL = "https://android.googleapis.com/attestation/status"

type config struct {
	port, packageName, extraRoots, statusSource string
	digests                                     [][]byte
	allowSoftware                               bool
}

func loadConfig() (config, error) {
	c := config{
		port:          getenv("PORT", "8080"),
		packageName:   os.Getenv("IRIS_PACKAGE_NAME"),
		extraRoots:    os.Getenv("IRIS_EXTRA_ROOTS_PEM"),
		statusSource:  getenv("IRIS_STATUS_SOURCE", statusURL),
		allowSoftware: os.Getenv("IRIS_ALLOW_SOFTWARE_ATTESTATION") == "true",
	}
	if c.packageName == "" {
		return c, errors.New("IRIS_PACKAGE_NAME is required")
	}
	for _, d := range strings.FieldsFunc(os.Getenv("IRIS_SIGNING_CERT_SHA256"), func(r rune) bool { return r == ',' }) {
		b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(d), ":", ""))
		if err != nil || len(b) != 32 {
			return c, fmt.Errorf("IRIS_SIGNING_CERT_SHA256: %q is not a SHA-256 digest", d)
		}
		c.digests = append(c.digests, b)
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	roots := attestation.GoogleRoots()
	if cfg.extraRoots != "" {
		data, err := os.ReadFile(cfg.extraRoots)
		if err != nil {
			return err
		}
		extra, err := attestation.ParsePEM(data)
		if err != nil {
			return fmt.Errorf("IRIS_EXTRA_ROOTS_PEM: %w", err)
		}
		roots = append(roots, extra...)
	}
	if len(cfg.digests) == 0 {
		log.Warn("IRIS_SIGNING_CERT_SHA256 not set: repackaged apps will not be detected")
	}
	if cfg.allowSoftware {
		log.Warn("software attestation allowed: test setups only")
	}

	store := challenge.NewStore(2*time.Minute, 100_000)
	v := verifier.New(verifier.Config{
		PackageName:              cfg.packageName,
		SigningCertDigests:       cfg.digests,
		Roots:                    roots,
		AllowSoftwareAttestation: cfg.allowSoftware,
		Challenges:               store,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go refreshStatus(ctx, log, v, cfg.statusSource)

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           routes(log, v, store),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "port", cfg.port, "package", cfg.packageName)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func routes(log *slog.Logger, v *verifier.Verifier, store *challenge.Store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /v1/challenge", func(w http.ResponseWriter, _ *http.Request) {
		c, err := store.Issue()
		if err != nil {
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"challenge": c, "expires_in": int(store.TTL().Seconds())})
	})
	mux.HandleFunc("POST /v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message        *verifier.Message `json:"message"`
			IntegrityToken string            `json:"integrity_token"`
		}
		body := http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(body).Decode(&req); err != nil || req.Message == nil {
			http.Error(w, "expected {\"message\": {...}, \"integrity_token\": \"...\"}", http.StatusBadRequest)
			return
		}
		d := v.Verify(r.Context(), req.Message, req.IntegrityToken)
		// Log the decision, not the report: evidence can contain device paths.
		log.Info("verify", "action", d.Action.String(), "reasons", len(d.Reasons))
		writeJSON(w, d)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// refreshStatus loads the revocation list now and every hour. Until the first load succeeds,
// decisions carry "revocation list unavailable" and escalate to review.
func refreshStatus(ctx context.Context, log *slog.Logger, v *verifier.Verifier, source string) {
	if source == "off" {
		log.Warn("attestation revocation list disabled")
		v.SetStatusList(&attestation.StatusList{})
		return
	}
	for {
		if s, err := loadStatus(ctx, source); err != nil {
			log.Warn("revocation list refresh failed", "err", err)
		} else {
			v.SetStatusList(s)
			log.Info("revocation list loaded", "entries", len(s.Entries))
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func loadStatus(ctx context.Context, source string) (*attestation.StatusList, error) {
	var data []byte
	if strings.HasPrefix(source, "https://") {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if err != nil {
			return nil, err
		}
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		if data, err = io.ReadAll(io.LimitReader(resp.Body, 16<<20)); err != nil {
			return nil, err
		}
	} else {
		var err error
		if data, err = os.ReadFile(source); err != nil {
			return nil, err
		}
	}
	var s attestation.StatusList
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}
