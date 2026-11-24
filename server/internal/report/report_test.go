package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseTheSDKFormat(t *testing.T) {
	// Exact output of Report.toJson() in core/ReportTest.
	r, err := Parse([]byte(`{"schema":1,"signals":[{"id":"HOOK-001","probe":"maps","evidence":"/tmp/frida-agent \"64\".so"}],"unavailable":[{"probe":"tracer","reason":"could not read /proc/self/status"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if r.Signals[0].Category() != "HOOK" || r.Unavailable[0].Probe != "tracer" {
		t.Fatalf("%+v", r)
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{`{"schema":2}`, `not json`, `{"schema":1,"signals":[{"id":"HOOK"}]}`} {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("accepted %s", in)
		}
	}
}

// The files in schema/examples are written by the SDK's ContractTest. Every one must parse,
// and re-encoding the parsed value must give back the same JSON: a field the SDK emits that
// this struct does not know would be lost here and fail the comparison.
func TestSharedExamples(t *testing.T) {
	files, err := filepath.Glob("../../../schema/examples/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no shared examples found: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		r, err := Parse(data)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		var want, got any
		_ = json.Unmarshal(data, &want)
		again, _ := json.Marshal(r)
		_ = json.Unmarshal(again, &got)
		if !reflect.DeepEqual(want, got) {
			t.Errorf("%s: round trip lost data\nwant %v\ngot  %v", filepath.Base(f), want, got)
		}
	}
}
