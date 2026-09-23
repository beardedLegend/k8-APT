package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "profile.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEmptyPathGivesDefaults(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("the defaults must be a valid profile: %v", err)
	}
	if c.TestDomain == "" || c.Image == "" || c.Log.Path == "" {
		t.Errorf("defaults are incomplete: %+v", c)
	}
}

func TestPartialProfileKeepsDefaults(t *testing.T) {
	c, err := Load(write(t, "testDomain: audit.example.test\nidleSample: 10m\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.TestDomain != "audit.example.test" {
		t.Errorf("testDomain = %q", c.TestDomain)
	}
	if c.IdleSample.Duration() != 10*time.Minute {
		t.Errorf("idleSample = %s", c.IdleSample.Duration())
	}
	if c.Image != Default().Image {
		t.Errorf("an unset field lost its default: image = %q", c.Image)
	}
	if len(c.Expect.StatusGroups) == 0 {
		t.Error("an unset list lost its default")
	}
}

func TestListsAreReplacedNotMerged(t *testing.T) {
	c, err := Load(write(t, "expect:\n  managedGroups: [system:nodes]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Expect.ManagedGroups) != 1 || c.Expect.ManagedGroups[0] != "system:nodes" {
		t.Errorf("managedGroups = %v, want exactly the configured list", c.Expect.ManagedGroups)
	}
}

func TestUnknownFieldIsRejected(t *testing.T) {
	if _, err := Load(write(t, "testDmoain: typo.example\n")); err == nil {
		t.Error("a misspelled field must be an error, not silently ignored")
	}
}

func TestValidate(t *testing.T) {
	for name, body := range map[string]string{
		"bad log type":      "log:\n  type: carrier-pigeon\n",
		"files without any": "log:\n  type: files\n",
		"empty domain":      "testDomain: \"\"\n",
		"domain with path":  "testDomain: example.com/x\n",
		"negative budget":   "budget:\n  gbPerYear: -1\n",
		"proxy without sa":  "components:\n  proxy:\n    enabled: true\n",
	} {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestRelativePathsResolveAgainstTheProfile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "profile.yaml")
	if err := os.WriteFile(p, []byte("kubeconfig: kube.conf\nlog:\n  type: files\n  files: [audit.log]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "kube.conf"); c.Kubeconfig != want {
		t.Errorf("kubeconfig = %q, want %q", c.Kubeconfig, want)
	}
	if want := filepath.Join(dir, "audit.log"); c.Log.Files[0] != want {
		t.Errorf("log.files[0] = %q, want %q", c.Log.Files[0], want)
	}
}

func TestAbsolutePathsAreLeftAlone(t *testing.T) {
	c, err := Load(write(t, "kubeconfig: /etc/kubernetes/admin.conf\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Kubeconfig != "/etc/kubernetes/admin.conf" {
		t.Errorf("kubeconfig = %q", c.Kubeconfig)
	}
}

func TestSudoDefaultsOn(t *testing.T) {
	c, _ := Load("")
	if !c.Log.SudoEnabled() {
		t.Error("audit logs are root-readable; sudo must default to on")
	}
	off, err := Load(write(t, "log:\n  sudo: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.Log.SudoEnabled() {
		t.Error("sudo: false was ignored")
	}
}

func TestDurationRoundTrips(t *testing.T) {
	c, _ := Load("")
	c.IdleSample = Duration(90 * time.Second)
	raw, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Load(write(t, string(raw)))
	if err != nil {
		t.Fatalf("a marshalled profile must load again: %v", err)
	}
	if back.IdleSample != c.IdleSample {
		t.Errorf("idleSample round-trip: %s != %s", back.IdleSample.Duration(), c.IdleSample.Duration())
	}
}
