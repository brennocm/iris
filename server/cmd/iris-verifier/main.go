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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/brennocm/iris/server/internal/attestation"
	"github.com/brennocm/iris/server/internal/challenge"
	"github.com/brennocm/iris/server/internal/integrity"
	"github.com/brennocm/iris/server/internal/ratelimit"
	"github.com/brennocm/iris/server/internal/verifier"
)

const statusURL = "https://android.googleapis.com/attestation/status"

type config struct {
	port, packageName, extraRoots, statusSource string
	digests                                     [][]byte
	allowSoftware                               bool
	redisURL, integrityCredentials, ipHeader    string
	ratePerMinute, rateBurst                    int
}

func loadConfig() (config, error) {
	c := config{
		port:                 getenv("PORT", "8080"),
		packageName:          os.Getenv("IRIS_PACKAGE_NAME"),
		extraRoots:           os.Getenv("IRIS_EXTRA_ROOTS_PEM"),
		statusSource:         getenv("IRIS_STATUS_SOURCE", statusURL),
		allowSoftware:        os.Getenv("IRIS_ALLOW_SOFTWARE_ATTESTATION") == "true",
		redisURL:             os.Getenv("IRIS_REDIS_URL"),
		integrityCredentials: os.Getenv("IRIS_PLAY_INTEGRITY_CREDENTIALS"),
		ipHeader:             os.Getenv("IRIS_CLIENT_IP_HEADER"),
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
	var err error
	if c.ratePerMinute, err = intEnv("IRIS_RATE_LIMIT_PER_MINUTE", 30); err != nil {
		return c, err
	}
	if c.rateBurst, err = intEnv("IRIS_RATE_LIMIT_BURST", 10); err != nil {
		return c, err
	}
	return c, nil
}

func getenv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func intEnv(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s: %q is not a positive integer", k, v)
	}
	return n, nil
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
		log.Warn("extra attestation roots trusted: test setups only", "count", len(extra))
	}
	if len(cfg.digests) == 0 {
		log.Warn("IRIS_SIGNING_CERT_SHA256 not set: repackaged apps will not be detected")
	}
	if cfg.allowSoftware {
		log.Warn("software attestation allowed: test setups only")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	d := deps{log: log, ipHeader: cfg.ipHeader, limiter: ratelimit.New(cfg.ratePerMinute, cfg.rateBurst, 100_000)}
	if cfg.redisURL != "" {
		r, err := challenge.NewRedis(cfg.redisURL, challengeTTL)
		if err != nil {
			return fmt.Errorf("IRIS_REDIS_URL: %w", err)
		}
		if err := r.Ping(ctx); err != nil {
			return fmt.Errorf("IRIS_REDIS_URL: %w", err)
		}
		d.store, d.redis = r, r
		log.Info("challenge store: redis")
	} else {
		d.store = challenge.NewMemory(challengeTTL, 100_000)
		log.Info("challenge store: memory (single instance only)")
	}

	vcfg := verifier.Config{
		PackageName:              cfg.packageName,
		SigningCertDigests:       cfg.digests,
		Roots:                    roots,
		AllowSoftwareAttestation: cfg.allowSoftware,
		Challenges:               d.store,
	}
	if cfg.integrityCredentials != "" {
		data, err := os.ReadFile(cfg.integrityCredentials)
		if err != nil {
			return fmt.Errorf("IRIS_PLAY_INTEGRITY_CREDENTIALS: %w", err)
		}
		sa, err := integrity.ParseServiceAccount(data, integrity.Scope)
		if err != nil {
			return fmt.Errorf("IRIS_PLAY_INTEGRITY_CREDENTIALS: %w", err)
		}
		vcfg.Integrity = &integrity.GoogleDecoder{Client: sa.Client(), PackageName: cfg.packageName}
		log.Info("play integrity: enabled")
	} else {
		log.Warn("IRIS_PLAY_INTEGRITY_CREDENTIALS not set: Play Integrity verdicts are not checked")
	}
	d.v = verifier.New(vcfg)
	go refreshStatus(ctx, log, d.v, cfg.statusSource)

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           routes(d),
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

const challengeTTL = 2 * time.Minute

// statusRetry is the first retry delay after a failed revocation list load (a var for tests).
var statusRetry = 30 * time.Second

type deps struct {
	log      *slog.Logger
	v        *verifier.Verifier
	store    challenge.Store
	redis    *challenge.Redis // nil with the memory store
	limiter  *ratelimit.Limiter
	ipHeader string
}

func routes(d deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	// Ready once the revocation list is loaded and the shared store answers.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if !d.v.StatusLoaded() {
			http.Error(w, "revocation list not loaded", http.StatusServiceUnavailable)
			return
		}
		if d.redis != nil {
			if err := d.redis.Ping(r.Context()); err != nil {
				http.Error(w, "challenge store unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	limited := func(h http.HandlerFunc) http.Handler { return d.limiter.Middleware(d.ipHeader, h) }
	mux.Handle("POST /v1/challenge", limited(func(w http.ResponseWriter, r *http.Request) {
		c, err := d.store.Issue(r.Context())
		if err != nil {
			d.log.Warn("challenge issue failed", "err", err)
			http.Error(w, "try again later", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, map[string]any{"challenge": c, "expires_in": int(d.store.TTL().Seconds())})
	}))
	mux.Handle("POST /v1/verify", limited(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Message        *verifier.Message `json:"message"`
			IntegrityToken string            `json:"integrity_token"`
		}
		body := http.MaxBytesReader(w, r.Body, 64<<10)
		if err := json.NewDecoder(body).Decode(&req); err != nil || req.Message == nil {
			http.Error(w, "expected {\"message\": {...}, \"integrity_token\": \"...\"}", http.StatusBadRequest)
			return
		}
		dec := d.v.Verify(r.Context(), req.Message, req.IntegrityToken)
		// Log the decision, not the report: evidence can contain device paths.
		d.log.Info("verify", "action", dec.Action.String(), "reasons", len(dec.Reasons))
		writeJSON(w, dec)
	}))
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
	// Refresh hourly. After a failure retry sooner, doubling up to the hourly interval, so an
	// instance that started during a network blip does not stay unready (/readyz) for an hour.
	retry := statusRetry
	for {
		wait := time.Hour
		if s, err := loadStatus(ctx, source); err != nil {
			log.Warn("revocation list refresh failed", "err", err, "retry_in", retry.String())
			wait, retry = retry, min(2*retry, time.Hour)
		} else {
			v.SetStatusList(s)
			log.Info("revocation list loaded", "entries", len(s.Entries))
			retry = statusRetry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
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
