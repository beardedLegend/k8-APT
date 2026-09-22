// Package k8apt provides the `go test` entry point to the same run the
// k8-apt binary performs, so that a cluster can be checked from CI with the
// tooling Go projects already have.
//
//	go test -count=1 -timeout 30m -v ./...
//
// Every expectation becomes a subtest, so a failure names the scenario and
// the check that broke. The run is configured exactly like the binary, by a
// cluster profile:
//
//	K8APT_CONFIG    path to the cluster profile (default: none, i.e. defaults)
//	K8APT_STRICT    "1" to fail on any difference from the baseline policy
//	K8APT_IDLE      idle this long first, to measure background log volume
//	K8APT_REPORT    write the markdown report here
//	K8APT_EVENTS    write every audit event of the run here (JSON lines)
package k8apt

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/your-org/k8-apt/internal/audit"
	"github.com/your-org/k8-apt/internal/config"
	"github.com/your-org/k8-apt/internal/runner"
)

func TestAuditPolicy(t *testing.T) {
	cfg, err := config.Load(os.Getenv("K8APT_CONFIG"))
	if err != nil {
		t.Fatalf("load cluster profile: %v", err)
	}
	if v := os.Getenv("K8APT_IDLE"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("K8APT_IDLE: %v", err)
		}
		cfg.IdleSample = config.Duration(d)
	}

	// Each expectation is reported as its own subtest as it is checked.
	observe := func(r *audit.Result) {
		t.Run(subtestName(r), func(t *testing.T) {
			switch r.Status() {
			case "FAIL":
				t.Errorf("%s\n    %s", r.Expect.Desc, strings.Join(r.Errors, "\n    "))
			case "DIFF":
				t.Logf("DIFFERS FROM BASELINE: %s\n    %s", r.Expect.Desc, strings.Join(r.Errors, "\n    "))
			case "GAP":
				t.Logf("KNOWN GAP: %s\n    %s\n    gap: %s", r.Expect.Desc, strings.Join(r.Errors, "\n    "), r.Expect.Gap)
			case "GAP-CLOSED":
				t.Logf("gap closed (the expectation now passes): %s", r.Expect.Desc)
			case "SKIP":
				t.Skip(r.Skipped)
			}
			if testing.Verbose() {
				for i, e := range r.Events {
					if i == 3 {
						t.Logf("      ... %d more", len(r.Events)-3)
						break
					}
					t.Logf("      %s", e.Short())
				}
			}
		})
	}

	res, err := runner.Run(context.Background(), cfg, runner.Options{
		Strict:     os.Getenv("K8APT_STRICT") == "1",
		ReportFile: os.Getenv("K8APT_REPORT"),
		EventsFile: os.Getenv("K8APT_EVENTS"),
		Log:        t.Logf,
		Observe:    observe,
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	runner.Report(res)
}

func subtestName(r *audit.Result) string {
	return r.Scenario + "/" + slug(r.Expect.Desc)
}

func slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case !dash && b.Len() > 0:
			b.WriteByte('-')
			dash = true
		}
	}
	return strings.Trim(b.String(), "-")
}
