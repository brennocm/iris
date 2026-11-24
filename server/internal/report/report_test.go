package report

import "testing"

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
