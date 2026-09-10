package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const minimalPolicy = `
default_discharge_ttl: 15m
credentials:
  - name: %s
    shared_secret_env: SHARED_SECRET
    rules:
      - name: r
        claims: {repository: acme/web}
`

// POLICY_YAML wins over POLICY_FILE, so the published image needs no mount.
func TestLoadPolicyPrefersInline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(fmtPolicy("from-file")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config{policyFile: path, policyInline: fmtPolicy("from-inline")}

	pol, source, err := cfg.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pol.Credentials[0].Name != "from-inline" || source != "$POLICY_YAML" {
		t.Errorf("loaded %q from %s, want from-inline from $POLICY_YAML", pol.Credentials[0].Name, source)
	}

	cfg.policyInline = ""
	pol, source, err = cfg.loadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if pol.Credentials[0].Name != "from-file" || source != path {
		t.Errorf("loaded %q from %s, want from-file from %s", pol.Credentials[0].Name, source, path)
	}
}

func TestLoadPolicyReportsAMissingFile(t *testing.T) {
	cfg := &config{policyFile: filepath.Join(t.TempDir(), "absent.yaml")}
	if _, _, err := cfg.loadPolicy(); err == nil {
		t.Fatal("a missing policy file must be an error")
	}
}

func TestConfigRequiresLocation(t *testing.T) {
	t.Setenv("OIDC_DISCHARGE_LOCATION", "")
	_, err := configFromEnv()
	if err == nil || !strings.Contains(err.Error(), "OIDC_DISCHARGE_LOCATION") {
		t.Fatalf("err = %v, want it to name OIDC_DISCHARGE_LOCATION", err)
	}
}

func TestConfigDefaultsAudienceToLocation(t *testing.T) {
	t.Setenv("OIDC_DISCHARGE_LOCATION", "https://discharge.example.com")
	t.Setenv("OIDC_AUDIENCE", "")
	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.audience != cfg.location {
		t.Errorf("audience = %q, want the location %q", cfg.audience, cfg.location)
	}
	if cfg.issuer != defaultIssuer {
		t.Errorf("issuer = %q, want the GitHub default", cfg.issuer)
	}
}

func fmtPolicy(name string) string {
	return strings.Replace(minimalPolicy, "%s", name, 1)
}
