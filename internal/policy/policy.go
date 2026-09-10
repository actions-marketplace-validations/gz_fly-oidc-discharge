// Package policy decides which GitHub Actions identities may discharge which
// Fly.io credential.
package policy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Claims that tie a rule to an identity. Every rule must set at least one, so
// that no rule is written with no identity constraint at all. How tightly it
// constrains stays the operator's choice: `repository: "*"` is accepted and
// matches every repository, which Warnings does not flag either.
var identityClaims = []string{"repository", "repository_owner", "sub", "job_workflow_ref"}

// Claims that identify the caller itself. job_workflow_ref is deliberately
// absent: it names the workflow file the job runs, which for a reusable
// workflow belongs to a different repository than the caller.
var callerClaims = []string{"repository", "repository_owner", "sub"}

// Claims that identify which workflow file, at which ref, is running. A rule
// that gates on `environment` without one of these trusts a claim any workflow
// in the repository can obtain by naming that environment.
var workflowClaims = []string{"ref", "job_workflow_ref"}

const sharedSecretBytes = 32

// Duration is a time.Duration that reads as "15m" in YAML.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(node *yaml.Node) error {
	var text string
	if err := node.Decode(&text); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

// Rule allows a discharge when every listed claim matches its pattern.
// Patterns are literal except for `*`, which matches any run of characters,
// including `/`.
type Rule struct {
	Name   string            `yaml:"name"`
	Claims map[string]string `yaml:"claims"`
}

// Credential is one Fly.io token, identified by the secret its third-party
// caveat was sealed with. Rules listed here govern that token alone.
type Credential struct {
	Name string `yaml:"name"`
	// SharedSecretEnv or SharedSecretFile locates the base64 secret passed to
	// `fly tokens 3p add --secret-file`. Exactly one is required.
	SharedSecretEnv  string `yaml:"shared_secret_env"`
	SharedSecretFile string `yaml:"shared_secret_file"`
	// DischargeTTL overrides the policy default for this credential.
	DischargeTTL Duration `yaml:"discharge_ttl"`
	Rules        []Rule   `yaml:"rules"`

	// Secret is filled by ResolveSecrets, never read from the policy file.
	Secret []byte `yaml:"-"`
}

type Policy struct {
	DefaultDischargeTTL Duration     `yaml:"default_discharge_ttl"`
	Credentials         []Credential `yaml:"credentials"`
}

func Load(path string) (*Policy, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(src)
}

func Parse(src []byte) (*Policy, error) {
	var p Policy
	dec := yaml.NewDecoder(bytes.NewReader(src))
	dec.KnownFields(true)
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	if err := p.validate(); err != nil {
		return nil, fmt.Errorf("invalid policy: %w", err)
	}
	return &p, nil
}

func (p *Policy) validate() error {
	if p.DefaultDischargeTTL <= 0 {
		return errors.New("default_discharge_ttl must be positive")
	}
	if len(p.Credentials) == 0 {
		return errors.New("no credentials")
	}
	seen := make(map[string]bool, len(p.Credentials))
	for i := range p.Credentials {
		credential := &p.Credentials[i]
		if credential.Name == "" {
			return fmt.Errorf("credential %d has no name", i)
		}
		if seen[credential.Name] {
			return fmt.Errorf("duplicate credential %q", credential.Name)
		}
		seen[credential.Name] = true
		if err := credential.validate(); err != nil {
			return fmt.Errorf("credential %q: %w", credential.Name, err)
		}
	}
	return nil
}

func (c *Credential) validate() error {
	switch {
	case c.SharedSecretEnv == "" && c.SharedSecretFile == "":
		return errors.New("set shared_secret_env or shared_secret_file")
	case c.SharedSecretEnv != "" && c.SharedSecretFile != "":
		return errors.New("set only one of shared_secret_env and shared_secret_file")
	case c.DischargeTTL < 0:
		return errors.New("discharge_ttl must be positive")
	case len(c.Rules) == 0:
		return errors.New("no rules, so nothing could ever discharge it")
	}
	for i, rule := range c.Rules {
		if rule.Name == "" {
			return fmt.Errorf("rule %d has no name", i)
		}
		if len(rule.Claims) == 0 {
			return fmt.Errorf("rule %q has no claims", rule.Name)
		}
		if !anyClaim(rule, identityClaims) {
			return fmt.Errorf("rule %q must constrain one of %s", rule.Name, strings.Join(identityClaims, ", "))
		}
		for claim, pattern := range rule.Claims {
			if claim == "" || pattern == "" {
				return fmt.Errorf("rule %q has an empty claim name or pattern", rule.Name)
			}
		}
	}
	return nil
}

// TTL is the validity window this credential's discharges get.
func (c *Credential) TTL(policyDefault Duration) time.Duration {
	if c.DischargeTTL > 0 {
		return time.Duration(c.DischargeTTL)
	}
	return time.Duration(policyDefault)
}

// ResolveSecrets loads every credential's shared secret and rejects a policy
// whose credentials cannot be told apart by their secrets.
func (p *Policy) ResolveSecrets() error {
	bySecret := make(map[string]string, len(p.Credentials))
	for i := range p.Credentials {
		credential := &p.Credentials[i]
		secret, err := credential.readSecret()
		if err != nil {
			return fmt.Errorf("credential %q: %w", credential.Name, err)
		}
		if owner, clash := bySecret[string(secret)]; clash {
			return fmt.Errorf("credentials %q and %q share a secret, so a ticket cannot select between them",
				owner, credential.Name)
		}
		bySecret[string(secret)] = credential.Name
		credential.Secret = secret
	}
	return nil
}

func (c *Credential) readSecret() ([]byte, error) {
	encoded := os.Getenv(c.SharedSecretEnv)
	source := "$" + c.SharedSecretEnv
	if c.SharedSecretFile != "" {
		raw, err := os.ReadFile(c.SharedSecretFile)
		if err != nil {
			return nil, fmt.Errorf("read shared_secret_file: %w", err)
		}
		encoded, source = string(raw), c.SharedSecretFile
	}
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("%s is empty", source)
	}
	secret, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode secret from %s: %w", source, err)
	}
	if len(secret) != sharedSecretBytes {
		return nil, fmt.Errorf("secret from %s must decode to %d bytes, got %d", source, sharedSecretBytes, len(secret))
	}
	return secret, nil
}

// Warnings reports rules whose claims are weaker than they look. They do not
// block startup; a deployment may rely on GitHub environment protection rules
// instead.
func (p *Policy) Warnings() []string {
	var warnings []string
	for _, credential := range p.Credentials {
		for _, rule := range credential.Rules {
			for _, warning := range rule.warnings() {
				warnings = append(warnings, fmt.Sprintf("credential %q rule %q %s", credential.Name, rule.Name, warning))
			}
		}
	}
	return warnings
}

func (r *Rule) warnings() []string {
	var warnings []string

	if _, gated := r.Claims["environment"]; gated && !anyClaim(*r, workflowClaims) {
		warnings = append(warnings, fmt.Sprintf(
			"gates on the environment claim without %s: any workflow in the repository can request that environment unless its deployment branch policy forbids it",
			strings.Join(workflowClaims, " or ")))
	}

	if _, pinned := r.Claims["job_workflow_ref"]; pinned && !anyClaim(*r, callerClaims) {
		warnings = append(warnings, fmt.Sprintf(
			"pins job_workflow_ref without %s: that claim names the workflow file, so a job in another repository that calls it as a reusable workflow carries the same value while keeping its own repository and ref",
			strings.Join(callerClaims, " or ")))
	}

	return warnings
}

// Match returns the first rule of this credential satisfied by claims. The
// error names, per rule, the claim that failed, so a denied job can be
// diagnosed from the log alone.
func (c *Credential) Match(claims map[string]string) (*Rule, error) {
	reasons := make([]string, 0, len(c.Rules))
	for i := range c.Rules {
		rule := &c.Rules[i]
		reason := rule.reject(claims)
		if reason == "" {
			return rule, nil
		}
		reasons = append(reasons, rule.Name+": "+reason)
	}
	return nil, fmt.Errorf("no rule of credential %q matches: %s", c.Name, strings.Join(reasons, "; "))
}

// reject returns why claims fail this rule, or "" when they satisfy it.
func (r *Rule) reject(claims map[string]string) string {
	// Sorted so the reason is deterministic for a given rule and claim set.
	names := make([]string, 0, len(r.Claims))
	for name := range r.Claims {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		value, ok := claims[name]
		if !ok {
			return fmt.Sprintf("claim %s missing", name)
		}
		if !Glob(r.Claims[name], value) {
			return fmt.Sprintf("claim %s=%q does not match %q", name, value, r.Claims[name])
		}
	}
	return ""
}

func anyClaim(rule Rule, names []string) bool {
	for _, name := range names {
		if _, ok := rule.Claims[name]; ok {
			return true
		}
	}
	return false
}

// Glob reports whether value matches pattern, where `*` matches any run of
// characters. Unlike path.Match, `*` also crosses `/`, so
// "refs/heads/gh-readonly-queue/*" covers every merge-queue ref.
func Glob(pattern, value string) bool {
	p, v := 0, 0
	starP, starV := -1, 0
	// Each iteration advances v or moves starV forward, so the loop runs at
	// most len(value)*(len(value)+1) times.
	for v < len(value) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			starP, starV = p, v
			p++
		case p < len(pattern) && pattern[p] == value[v]:
			p++
			v++
		case starP >= 0:
			// Backtrack: let the most recent `*` absorb one more character.
			starV++
			p, v = starP+1, starV
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
