// Package report parses the JSON report produced by the Iris SDK (Report.toJson).
package report

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SchemaVersion is the report schema this server understands.
const SchemaVersion = 1

type Signal struct {
	ID       string `json:"id"`
	Probe    string `json:"probe"`
	Evidence string `json:"evidence"`
}

type Unavailable struct {
	Probe  string `json:"probe"`
	Reason string `json:"reason"`
}

type Report struct {
	Schema      int           `json:"schema"`
	Signals     []Signal      `json:"signals"`
	Unavailable []Unavailable `json:"unavailable"`
}

// Category is the part of the signal code before the dash: ROOT, HOOK, DEBUG or TAMPER.
func (s Signal) Category() string {
	cat, _, _ := strings.Cut(s.ID, "-")
	return cat
}

// Parse decodes and validates a report.
func Parse(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("report: %w", err)
	}
	if r.Schema != SchemaVersion {
		return nil, fmt.Errorf("report: unsupported schema %d", r.Schema)
	}
	for _, s := range r.Signals {
		if s.Category() == s.ID || s.ID == "" {
			return nil, fmt.Errorf("report: malformed signal id %q", s.ID)
		}
	}
	return &r, nil
}
