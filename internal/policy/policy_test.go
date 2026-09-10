package policy

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const twoCredentials = `
default_discharge_ttl: 15m
credentials:
  - name: prod
    shared_secret_env: SHARED_SECRET_PROD
    discharge_ttl: 10m
    rules:
      - name: prod deploy
        claims:
          job_workflow_ref: acme/web/.github/workflows/deploy.yml@refs/heads/main
          environment: prod
  - name: ci
    shared_secret_env: SHARED_SECRET_CI
    rules:
      - name: main
        claims:
          repository: acme/web
          ref: refs/heads/main
      - name: merge queue
        claims:
          repository: acme/web
          event_name: merge_group
          ref: refs/heads/gh-readonly-queue/main/*
`

func credential(t *testing.T, pol *Policy, name string) *Credential {
	t.Helper()
	for i := range pol.Credentials {
		if pol.Credentials[i].Name == name {
			return &pol.Credentials[i]
		}
	}
	t.Fatalf("no credential %q", name)
	return nil
}

// Glob treats `*` as any run of characters, including `/`.
func TestGlob(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"refs/heads/main", "refs/heads/main", true},
		{"refs/heads/main", "refs/heads/main2", false},
		{"refs/heads/main", "refs/heads/mai", false},
		{"refs/heads/gh-readonly-queue/*", "refs/heads/gh-readonly-queue/main/pr-12-abc", true},
		{"refs/heads/gh-readonly-queue/*", "refs/heads/main", false},
		// A `*` must absorb `/` even when the value's next byte is `/`.
		{"refs/heads/gh-readonly-queue*", "refs/heads/gh-readonly-queue/main/pr-12-abc", true},
		{"repo:acme/we*:ref:refs/heads/main", "repo:acme/web:ref:refs/heads/main", true},
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"a*b*c", "aXXbYYc", true},
		{"a*b*c", "aXXbYY", false},
		{"a**c", "ac", true},
		{"", "", true},
		{"", "x", false},
		{"acme/*", "acme/web", true},
		{"acme/*", "evil/acme/x", false},
	}
	for _, c := range cases {
		if got := Glob(c.pattern, c.value); got != c.want {
			t.Errorf("Glob(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

// Rules of one credential never admit an identity to another credential.
func TestMatchIsScopedToItsCredential(t *testing.T) {
	pol, err := Parse([]byte(twoCredentials))
	must(t, err)
	ciIdentity := map[string]string{
		"repository": "acme/web",
		"ref":        "refs/heads/main",
		"event_name": "push",
	}
	if _, err := credential(t, pol, "ci").Match(ciIdentity); err != nil {
		t.Errorf("ci identity denied by the ci credential: %v", err)
	}
	if rule, err := credential(t, pol, "prod").Match(ciIdentity); err == nil {
		t.Errorf("ci identity allowed to discharge prod via rule %q", rule.Name)
	}
}

func TestMatch(t *testing.T) {
	pol, err := Parse([]byte(twoCredentials))
	must(t, err)
	prodIdentity := map[string]string{
		"job_workflow_ref": "acme/web/.github/workflows/deploy.yml@refs/heads/main",
		"environment":      "prod",
	}
	cases := []struct {
		name       string
		credential string
		claims     map[string]string
		wantRule   string
	}{
		{"prod deploy", "prod", prodIdentity, "prod deploy"},
		{"prod workflow on another branch", "prod", map[string]string{
			"job_workflow_ref": "acme/web/.github/workflows/deploy.yml@refs/pull/9/merge",
			"environment":      "prod",
		}, ""},
		{"staging environment asking for prod", "prod", map[string]string{
			"job_workflow_ref": "acme/web/.github/workflows/deploy.yml@refs/heads/main",
			"environment":      "staging",
		}, ""},
		{"no environment claim at all", "prod", map[string]string{
			"job_workflow_ref": "acme/web/.github/workflows/deploy.yml@refs/heads/main",
		}, ""},
		{"merge queue", "ci", map[string]string{
			"repository": "acme/web",
			"ref":        "refs/heads/gh-readonly-queue/main/pr-7-abc",
			"event_name": "merge_group",
		}, "merge queue"},
		{"feature branch", "ci", map[string]string{
			"repository": "acme/web",
			"ref":        "refs/heads/feature",
		}, ""},
		{"other repository", "ci", map[string]string{
			"repository": "evil/web",
			"ref":        "refs/heads/main",
		}, ""},
		{"no claims", "ci", map[string]string{}, ""},
	}
	for _, c := range cases {
		rule, err := credential(t, pol, c.credential).Match(c.claims)
		switch {
		case c.wantRule == "" && err == nil:
			t.Errorf("%s: allowed by rule %q, want denial", c.name, rule.Name)
		case c.wantRule != "" && err != nil:
			t.Errorf("%s: denied (%v), want rule %q", c.name, err, c.wantRule)
		case c.wantRule != "" && rule.Name != c.wantRule:
			t.Errorf("%s: matched rule %q, want %q", c.name, rule.Name, c.wantRule)
		}
	}
}

// job_workflow_ref names the workflow, not the caller: a job in another
// repository can call the same reusable workflow and carry the identical claim.
// A caller claim is what keeps it out.
func TestJobWorkflowRefAloneDoesNotBoundTheCaller(t *testing.T) {
	const workflowRef = "acme/web/.github/workflows/deploy.yml@refs/heads/main"
	outsider := map[string]string{
		"repository":       "outsider/repo",
		"ref":              "refs/heads/untrusted",
		"job_workflow_ref": workflowRef,
		"environment":      "prod",
	}
	rule := func(claims string) *Credential {
		pol, err := Parse([]byte("default_discharge_ttl: 15m\ncredentials:\n  - name: prod\n" +
			"    shared_secret_env: S\n    rules:\n      - name: prod deploy\n        claims:\n" + claims))
		must(t, err)
		return &pol.Credentials[0]
	}

	workflowOnly := rule("          job_workflow_ref: " + workflowRef + "\n          environment: prod\n")
	if _, err := workflowOnly.Match(outsider); err != nil {
		t.Errorf("workflow-only rule should admit the outsider, showing why it is insufficient: %v", err)
	}

	withCaller := rule("          repository: acme/web\n          job_workflow_ref: " + workflowRef +
		"\n          environment: prod\n")
	if _, err := withCaller.Match(outsider); err == nil {
		t.Error("a rule pinning the caller repository must deny a cross-repository caller")
	}

	// The intended caller still passes.
	insider := map[string]string{
		"repository":       "acme/web",
		"ref":              "refs/heads/main",
		"job_workflow_ref": workflowRef,
		"environment":      "prod",
	}
	if _, err := withCaller.Match(insider); err != nil {
		t.Errorf("the intended caller was denied: %v", err)
	}
}

// A denial names the credential and the failing claim per rule.
func TestMatchErrorNamesFailingClaim(t *testing.T) {
	pol, err := Parse([]byte(twoCredentials))
	must(t, err)
	_, err = credential(t, pol, "ci").Match(map[string]string{
		"repository": "acme/web",
		"ref":        "refs/heads/feature",
	})
	if err == nil {
		t.Fatal("expected denial")
	}
	for _, want := range []string{
		`credential "ci"`,
		`main: claim ref="refs/heads/feature" does not match "refs/heads/main"`,
		`merge queue: claim event_name missing`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
}

func TestTTLFallsBackToPolicyDefault(t *testing.T) {
	pol, err := Parse([]byte(twoCredentials))
	must(t, err)
	if got := credential(t, pol, "prod").TTL(pol.DefaultDischargeTTL); got != 10*time.Minute {
		t.Errorf("prod TTL = %s, want 10m", got)
	}
	if got := credential(t, pol, "ci").TTL(pol.DefaultDischargeTTL); got != 15*time.Minute {
		t.Errorf("ci TTL = %s, want the 15m default", got)
	}
}

// Parse refuses policies that could match arbitrary repositories, name no
// secret, or hide a typo.
func TestParseRejectsUnsafePolicies(t *testing.T) {
	cases := map[string]string{
		"empty document":           "",
		"no credentials":           "default_discharge_ttl: 15m\ncredentials: []",
		"no default ttl":           "credentials:\n  - name: a\n    shared_secret_env: S\n    rules:\n      - name: r\n        claims: {repository: a/b}",
		"unnamed credential":       "default_discharge_ttl: 15m\ncredentials:\n  - shared_secret_env: S\n    rules:\n      - name: r\n        claims: {repository: a/b}",
		"duplicate credential":     "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S1\n    rules: [{name: r, claims: {repository: a/b}}]\n  - name: a\n    shared_secret_env: S2\n    rules: [{name: r, claims: {repository: a/b}}]",
		"no secret source":         "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    rules: [{name: r, claims: {repository: a/b}}]",
		"two secret sources":       "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    shared_secret_file: /f\n    rules: [{name: r, claims: {repository: a/b}}]",
		"credential without rules": "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: []",
		"unnamed rule":             "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: [{claims: {repository: a/b}}]",
		"rule without claims":      "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: [{name: r}]",
		"rule without repository":  "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: [{name: r, claims: {ref: refs/heads/main}}]",
		"empty pattern":            "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: [{name: r, claims: {repository: \"\"}}]",
		"misspelled field":         "default_discharge_ttl: 15m\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rule: [{name: r, claims: {repository: a/b}}]",
		"unparseable ttl":          "default_discharge_ttl: fortnight\ncredentials:\n  - name: a\n    shared_secret_env: S\n    rules: [{name: r, claims: {repository: a/b}}]",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestResolveSecrets(t *testing.T) {
	secret := base64.StdEncoding.EncodeToString(make([]byte, 32))
	other := base64.StdEncoding.EncodeToString(append(make([]byte, 31), 1))

	t.Run("from env and file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "secret.b64")
		must(t, os.WriteFile(path, []byte(other+"\n"), 0o600))
		t.Setenv("SHARED_SECRET_PROD", secret)
		pol, err := Parse([]byte("default_discharge_ttl: 15m\ncredentials:\n" +
			"  - name: prod\n    shared_secret_env: SHARED_SECRET_PROD\n    rules: [{name: r, claims: {repository: a/b}}]\n" +
			"  - name: ci\n    shared_secret_file: " + path + "\n    rules: [{name: r, claims: {repository: a/b}}]"))
		must(t, err)
		must(t, pol.ResolveSecrets())
		if len(credential(t, pol, "prod").Secret) != 32 || len(credential(t, pol, "ci").Secret) != 32 {
			t.Fatal("secrets not resolved to 32 bytes")
		}
	})

	// Two credentials sharing a secret cannot be told apart by a ticket, so
	// one would silently answer for the other.
	t.Run("shared secret between credentials", func(t *testing.T) {
		t.Setenv("SHARED_SECRET_A", secret)
		t.Setenv("SHARED_SECRET_B", secret)
		pol, err := Parse([]byte("default_discharge_ttl: 15m\ncredentials:\n" +
			"  - name: a\n    shared_secret_env: SHARED_SECRET_A\n    rules: [{name: r, claims: {repository: a/b}}]\n" +
			"  - name: b\n    shared_secret_env: SHARED_SECRET_B\n    rules: [{name: r, claims: {repository: a/b}}]"))
		must(t, err)
		err = pol.ResolveSecrets()
		if err == nil || !strings.Contains(err.Error(), "share a secret") {
			t.Fatalf("err = %v, want a shared-secret clash", err)
		}
	})

	t.Run("bad secrets", func(t *testing.T) {
		for name, value := range map[string]string{
			"missing":      "",
			"not base64":   "!!!!",
			"wrong length": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		} {
			t.Setenv("SHARED_SECRET_PROD", value)
			pol, err := Parse([]byte("default_discharge_ttl: 15m\ncredentials:\n" +
				"  - name: prod\n    shared_secret_env: SHARED_SECRET_PROD\n    rules: [{name: r, claims: {repository: a/b}}]"))
			must(t, err)
			if err := pol.ResolveSecrets(); err == nil {
				t.Errorf("%s secret accepted", name)
			}
		}
	})
}

// Warnings flags rules whose claims are weaker than they look, without
// blocking startup.
func TestWarnings(t *testing.T) {
	base := "default_discharge_ttl: 15m\ncredentials:\n  - name: prod\n    shared_secret_env: S\n    rules:\n      - name: r\n        claims:\n"
	const (
		environmentWarning = "gates on the environment claim"
		callerWarning      = "pins job_workflow_ref without"
	)
	cases := map[string]struct {
		claims string
		want   []string
	}{
		"environment with only a repository": {
			"          repository: a/b\n          environment: prod\n",
			[]string{environmentWarning},
		},
		"environment with a ref": {
			"          repository: a/b\n          environment: prod\n          ref: refs/heads/main\n",
			nil,
		},
		// job_workflow_ref satisfies the environment check but names the
		// workflow, not the caller, so the caller warning applies instead.
		"workflow ref alone": {
			"          job_workflow_ref: a/b/.github/workflows/w.yml@refs/heads/main\n          environment: prod\n",
			[]string{callerWarning},
		},
		"workflow ref with the caller's repository": {
			"          repository: a/b\n          job_workflow_ref: a/b/.github/workflows/w.yml@refs/heads/main\n          environment: prod\n",
			nil,
		},
		"no environment and no workflow ref": {
			"          repository: a/b\n          ref: refs/heads/main\n",
			nil,
		},
		// The wildcard is the operator's call, so nothing is reported.
		"wildcard repository": {
			"          repository: \"*\"\n",
			nil,
		},
	}
	for name, c := range cases {
		pol, err := Parse([]byte(base + c.claims))
		must(t, err)
		got := pol.Warnings()
		if len(got) != len(c.want) {
			t.Errorf("%s: %d warnings, want %d: %v", name, len(got), len(c.want), got)
			continue
		}
		for i, want := range c.want {
			if !strings.Contains(got[i], want) {
				t.Errorf("%s: warning %q lacks %q", name, got[i], want)
			}
		}
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
