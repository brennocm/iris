// Package integrity checks a decoded Play Integrity verdict against the Iris report it should
// be bound to.
package integrity

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"time"
)

// Verdict is the subset of the decoded token payload this server uses.
type Verdict struct {
	RequestDetails struct {
		RequestPackageName string `json:"requestPackageName"`
		RequestHash        string `json:"requestHash"`
		TimestampMillis    string `json:"timestampMillis"`
	} `json:"requestDetails"`
	AppIntegrity struct {
		AppRecognitionVerdict string `json:"appRecognitionVerdict"`
		PackageName           string `json:"packageName"`
	} `json:"appIntegrity"`
	DeviceIntegrity struct {
		DeviceRecognitionVerdict []string `json:"deviceRecognitionVerdict"`
	} `json:"deviceIntegrity"`
}

// Problems lists everything wrong with the verdict, in plain words. Empty means it passes.
// requestHash must be the hex SHA-256 of the report bytes (IrisMessage.requestHash()).
func (v *Verdict) Problems(packageName, requestHash string, now time.Time, maxAge time.Duration) []string {
	var out []string
	if v.RequestDetails.RequestPackageName != packageName {
		out = append(out, "integrity token is for another package")
	}
	if v.RequestDetails.RequestHash != requestHash {
		out = append(out, "integrity token is not bound to this report")
	}
	if ms, err := strconv.ParseInt(v.RequestDetails.TimestampMillis, 10, 64); err != nil {
		out = append(out, "integrity token has no timestamp")
	} else if age := now.Sub(time.UnixMilli(ms)); age > maxAge || age < -maxAge {
		out = append(out, "integrity token is stale")
	}
	if v.AppIntegrity.AppRecognitionVerdict != "PLAY_RECOGNIZED" {
		out = append(out, "app not recognized by Play: "+v.AppIntegrity.AppRecognitionVerdict)
	}
	if !slices.Contains(v.DeviceIntegrity.DeviceRecognitionVerdict, "MEETS_DEVICE_INTEGRITY") {
		out = append(out, "device does not meet device integrity")
	}
	return out
}

// Decoder turns an integrity token into a verdict.
type Decoder interface {
	Decode(ctx context.Context, token string) (*Verdict, error)
}

// GoogleDecoder calls the Play Integrity API. Client must already be authenticated with a
// service account that has access to the app (for example
// golang.org/x/oauth2/google.DefaultClient with the playintegrity scope).
type GoogleDecoder struct {
	Client      *http.Client
	PackageName string
	Endpoint    string // defaults to the public API; overridden in tests
}

func (d *GoogleDecoder) Decode(ctx context.Context, token string) (*Verdict, error) {
	endpoint := d.Endpoint
	if endpoint == "" {
		endpoint = "https://playintegrity.googleapis.com"
	}
	url := fmt.Sprintf("%s/v1/%s:decodeIntegrityToken", endpoint, d.PackageName)
	body, _ := json.Marshal(map[string]string{"integrityToken": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("play integrity: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("play integrity: HTTP %d", resp.StatusCode)
	}
	var out struct {
		TokenPayloadExternal *Verdict `json:"tokenPayloadExternal"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.TokenPayloadExternal == nil {
		return nil, fmt.Errorf("play integrity: unexpected response")
	}
	return out.TokenPayloadExternal, nil
}
