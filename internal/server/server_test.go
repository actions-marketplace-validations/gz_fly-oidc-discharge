package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/tp"

	"github.com/gz/fly-oidc-discharge/internal/policy"
)

const (
	flyLocation       = "https://api.fly.io/v1"
	dischargeLocation = "https://fly-oidc-discharge.test"
	workflowRef       = "acme/web/.github/workflows/deploy.yml@refs/heads/main"
	prodTTL           = 10 * time.Minute
	defaultTTL        = 15 * time.Minute

	testPolicy = `
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
  - name: staging
    shared_secret_env: SHARED_SECRET_STAGING
    rules:
      - name: staging deploy
        claims:
          job_workflow_ref: acme/web/.github/workflows/deploy.yml@refs/heads/main
          environment: staging
`
)

func identity(environment string) map[string]string {
	return map[string]string{
		"repository":       "acme/web",
		"ref":              "refs/heads/main",
		"job_workflow_ref": workflowRef,
		"environment":      environment,
		"event_name":       "push",
		"actor":            "octocat",
	}
}

// issuer is a fake GitHub OIDC provider: discovery document, JWKS, and signer.
type issuer struct {
	url    string
	signer jose.Signer
}

func newIssuer(t *testing.T) *issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)

	iss := &issuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		must(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.url,
			"jwks_uri":                              iss.url + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		must(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}}))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	iss.url = srv.URL

	iss.signer, err = jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	must(t, err)
	return iss
}

func (iss *issuer) token(t *testing.T, audience string, claims map[string]string) string {
	t.Helper()
	return iss.tokenExpiring(t, audience, claims, time.Now().Add(5*time.Minute))
}

func (iss *issuer) tokenExpiring(t *testing.T, audience string, claims map[string]string, expiry time.Time) string {
	t.Helper()
	standard := jwt.Claims{
		Issuer:   iss.url,
		Subject:  "repo:" + claims["repository"] + ":environment:" + claims["environment"],
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(expiry.Add(-10 * time.Minute)),
		Expiry:   jwt.NewNumericDate(expiry),
	}
	custom := make(map[string]any, len(claims))
	for name, value := range claims {
		custom[name] = value
	}
	raw, err := jwt.Signed(iss.signer).Claims(standard).Claims(custom).Serialize()
	must(t, err)
	return raw
}

type fixture struct {
	handler http.Handler
	iss     *issuer
	pol     *policy.Policy
	// perSecond and burst are zero unless a test narrows them, which selects
	// the production defaults.
	perSecond float64
	burst     float64
	// rootKey plays Fly's signing key for the permission token.
	rootKey macaroon.SigningKey
	now     time.Time
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWithLimits(t, 0, 0)
}

func newFixtureWithLimits(t *testing.T, perSecond, burst float64) *fixture {
	t.Helper()
	t.Setenv("SHARED_SECRET_PROD", base64.StdEncoding.EncodeToString(randomKey(t)))
	t.Setenv("SHARED_SECRET_STAGING", base64.StdEncoding.EncodeToString(randomKey(t)))
	pol, err := policy.Parse([]byte(testPolicy))
	must(t, err)
	must(t, pol.ResolveSecrets())

	iss := newIssuer(t)
	verifier := NewVerifier(iss.url, dischargeLocation)

	log := logrus.New()
	log.SetOutput(io.Discard)
	f := &fixture{
		iss:       iss,
		pol:       pol,
		perSecond: perSecond,
		burst:     burst,
		rootKey:   macaroon.NewSigningKey(),
		now:       time.Unix(1_800_000_000, 0),
	}
	f.handler, err = New(Config{
		Location:          dischargeLocation,
		Policy:            pol,
		Verifier:          verifier,
		Log:               log,
		RequestsPerSecond: f.perSecond,
		RequestBurst:      f.burst,
		Now:               func() time.Time { return f.now },
	})
	must(t, err)
	return f
}

func randomKey(t *testing.T) []byte {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	must(t, err)
	return key
}

func (f *fixture) secret(t *testing.T, name string) macaroon.EncryptionKey {
	t.Helper()
	for i := range f.pol.Credentials {
		if f.pol.Credentials[i].Name == name {
			return f.pol.Credentials[i].Secret
		}
	}
	t.Fatalf("no credential %q", name)
	return nil
}

// caveatedToken mints what `fly tokens create` + `fly tokens 3p add` produce
// for one credential's shared secret.
func (f *fixture) caveatedToken(t *testing.T, secret macaroon.EncryptionKey, ticketCaveats ...macaroon.Caveat) *macaroon.Macaroon {
	t.Helper()
	m, err := macaroon.New([]byte("kid"), flyLocation, f.rootKey)
	must(t, err)
	must(t, m.Add3P(secret, dischargeLocation, ticketCaveats...))
	return m
}

// ticket extracts what `fly tokens 3p ticket` prints.
func (f *fixture) ticket(t *testing.T, m *macaroon.Macaroon) []byte {
	t.Helper()
	ticket, err := m.ThirdPartyTicket(dischargeLocation)
	must(t, err)
	if len(ticket) == 0 {
		t.Fatal("token has no ticket for the discharge location")
	}
	return ticket
}

// ticketFor is the common case: a caveated token for one named credential.
func (f *fixture) ticketFor(t *testing.T, name string) []byte {
	t.Helper()
	return f.ticket(t, f.caveatedToken(t, f.secret(t, name)))
}

func (f *fixture) post(t *testing.T, authorization string, ticket []byte) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string][]byte{"ticket": ticket})
	must(t, err)
	req := httptest.NewRequest(http.MethodPost, tp.InitPath, bytes.NewReader(body))
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	return rec
}

// exchange runs the whole flow for one environment against one credential.
func (f *fixture) exchange(t *testing.T, environment, credentialName string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, "Bearer "+f.iss.token(t, dischargeLocation, identity(environment)), f.ticketFor(t, credentialName))
}

type response struct {
	Discharge string `json:"discharge"`
	Error     string `json:"error"`
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) response {
	t.Helper()
	var resp response
	must(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

// at implements macaroon.Access with a fixed clock, for evaluating ValidityWindow.
type at time.Time

func (a at) Now() time.Time  { return time.Time(a) }
func (a at) Validate() error { return nil }

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// The credential a ticket belongs to is discharged with its own TTL, and the
// response names it.
func TestDischargesEachCredential(t *testing.T) {
	for _, c := range []struct {
		environment string
		credential  string
		ttl         time.Duration
	}{
		{"prod", "prod", prodTTL},
		{"staging", "staging", defaultTTL},
	} {
		t.Run(c.credential, func(t *testing.T) {
			f := newFixture(t)
			m := f.caveatedToken(t, f.secret(t, c.credential))
			rec := f.post(t, "Bearer "+f.iss.token(t, dischargeLocation, identity(c.environment)), f.ticket(t, m))
			if rec.Code != http.StatusCreated {
				t.Fatalf("status %d, body %s", rec.Code, rec.Body)
			}
			if got := rec.Header().Get(headerCredential); got != c.credential {
				t.Errorf("%s = %q, want %q", headerCredential, got, c.credential)
			}
			discharges, err := macaroon.Parse(decode(t, rec).Discharge)
			must(t, err)

			// Fly's side of verification: permission token plus discharge.
			caveats, err := m.Verify(f.rootKey, discharges, nil)
			must(t, err)
			windows := macaroon.GetCaveats[*macaroon.ValidityWindow](caveats)
			if len(windows) != 1 {
				t.Fatalf("got %d validity windows, want 1", len(windows))
			}
			if want := f.now.Add(c.ttl).Unix(); windows[0].NotAfter != want {
				t.Errorf("NotAfter = %d, want %d", windows[0].NotAfter, want)
			}
			if err := windows[0].Prohibits(at(f.now.Add(c.ttl + time.Second))); err == nil {
				t.Error("window still valid one second after the TTL")
			}
		})
	}
}

// The point of separate credentials: a staging job holding the prod caveated
// token is refused, and a prod job cannot use the staging one either.
func TestCredentialsAreIsolatedByEnvironment(t *testing.T) {
	cases := []struct {
		name        string
		environment string
		credential  string
	}{
		{"staging job, prod credential", "staging", "prod"},
		{"prod job, staging credential", "prod", "staging"},
		{"no environment, prod credential", "", "prod"},
		{"unknown environment, prod credential", "development", "prod"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			rec := f.exchange(t, c.environment, c.credential)
			assertDenied(t, rec, http.StatusForbidden)
			if !bytes.Contains(rec.Body.Bytes(), []byte(c.credential)) {
				t.Errorf("error should name credential %q: %s", c.credential, rec.Body)
			}
			if got := rec.Header().Get(headerCredential); got != "" {
				t.Errorf("a denied request must not name a credential, got %q", got)
			}
		})
	}
}

// The secret selects the credential, so the rules applied are the ones of the
// credential whose secret sealed the ticket, never another credential's.
func TestSecretSelectsWhichRulesApply(t *testing.T) {
	f := newFixture(t)
	// This identity satisfies the staging rules and no others.
	authorization := "Bearer " + f.iss.token(t, dischargeLocation, identity("staging"))

	if rec := f.post(t, authorization, f.ticketFor(t, "staging")); rec.Code != http.StatusCreated {
		t.Fatalf("staging ticket: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := f.post(t, authorization, f.ticketFor(t, "prod")); rec.Code != http.StatusForbidden {
		t.Fatalf("prod ticket: status %d, want 403; body %s", rec.Code, rec.Body)
	}
}

func TestRejectsMissingBearer(t *testing.T) {
	f := newFixture(t)
	assertDenied(t, f.post(t, "", f.ticketFor(t, "prod")), http.StatusUnauthorized)
}

func TestRejectsTokenForOtherAudience(t *testing.T) {
	f := newFixture(t)
	rec := f.post(t, "Bearer "+f.iss.token(t, "https://elsewhere.test", identity("prod")), f.ticketFor(t, "prod"))
	assertDenied(t, rec, http.StatusUnauthorized)
}

func TestRejectsExpiredToken(t *testing.T) {
	f := newFixture(t)
	expired := f.iss.tokenExpiring(t, dischargeLocation, identity("prod"), time.Now().Add(-time.Minute))
	assertDenied(t, f.post(t, "Bearer "+expired, f.ticketFor(t, "prod")), http.StatusUnauthorized)
}

func TestRejectsTokenFromUnknownIssuer(t *testing.T) {
	f := newFixture(t)
	other := newIssuer(t)
	rec := f.post(t, "Bearer "+other.token(t, dischargeLocation, identity("prod")), f.ticketFor(t, "prod"))
	assertDenied(t, rec, http.StatusUnauthorized)
}

func TestRejectsTicketWithEmbeddedCaveats(t *testing.T) {
	f := newFixture(t)
	m := f.caveatedToken(t, f.secret(t, "prod"), &macaroon.ValidityWindow{NotBefore: 0, NotAfter: f.now.Unix()})
	rec := f.post(t, "Bearer "+f.iss.token(t, dischargeLocation, identity("prod")), f.ticket(t, m))
	assertDenied(t, rec, http.StatusBadRequest)
}

// A ticket sealed under a secret no credential holds is a configuration error,
// reported as such rather than as a server fault.
func TestRejectsTicketForUnknownSecret(t *testing.T) {
	f := newFixture(t)
	m := f.caveatedToken(t, macaroon.NewEncryptionKey())
	rec := f.post(t, "Bearer "+f.iss.token(t, dischargeLocation, identity("prod")), f.ticket(t, m))
	assertDenied(t, rec, http.StatusBadRequest)
	if !bytes.Contains(rec.Body.Bytes(), []byte("shared secret")) {
		t.Errorf("error should name the shared secret: %s", rec.Body)
	}
}

func TestRejectsMalformedBody(t *testing.T) {
	f := newFixture(t)
	authorization := "Bearer " + f.iss.token(t, dischargeLocation, identity("prod"))
	for name, body := range map[string]string{
		"not json":       "{",
		"ticket missing": `{}`,
		"ticket empty":   `{"ticket":""}`,
		"ticket garbage": `{"ticket":"bm90LWEtdGlja2V0"}`,
	} {
		req := httptest.NewRequest(http.MethodPost, tp.InitPath, bytes.NewReader([]byte(body)))
		req.Header.Set("Authorization", authorization)
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400; body %s", name, rec.Code, rec.Body)
		}
	}
}

func TestHealthzAndMethodGuard(t *testing.T) {
	f := newFixture(t)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tp.InitPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET %s status %d, want 405", tp.InitPath, rec.Code)
	}
}

func TestNewRequiresResolvedSecrets(t *testing.T) {
	pol, err := policy.Parse([]byte(testPolicy))
	must(t, err)
	log := logrus.New()
	log.SetOutput(io.Discard)
	_, err = New(Config{Location: dischargeLocation, Policy: pol, Verifier: stubVerifier{}, Log: log})
	if err == nil {
		t.Fatal("accepted a policy whose secrets were never resolved")
	}
}

type stubVerifier struct{}

func (stubVerifier) Claims(context.Context, string) (map[string]string, error) { return nil, nil }

func assertDenied(t *testing.T, rec *httptest.ResponseRecorder, wantStatus int) {
	t.Helper()
	if rec.Code != wantStatus {
		t.Errorf("status %d, want %d; body %s", rec.Code, wantStatus, rec.Body)
	}
	if resp := decode(t, rec); resp.Discharge != "" || resp.Error == "" {
		t.Errorf("denied response must carry an error and no discharge: %s", rec.Body)
	}
}

// countingVerifier records how often a request reached OIDC verification.
type countingVerifier struct{ calls atomic.Int32 }

func (c *countingVerifier) Claims(context.Context, string) (map[string]string, error) {
	c.calls.Add(1)
	return nil, errors.New("not a real token")
}

// Past the burst the endpoint answers 429 without spending any OIDC work,
// which is what bounds the outbound key fetches a stranger can drive.
func TestRateLimitedBeforeVerification(t *testing.T) {
	pol, err := policy.Parse([]byte(testPolicy))
	must(t, err)
	t.Setenv("SHARED_SECRET_PROD", base64.StdEncoding.EncodeToString(randomKey(t)))
	t.Setenv("SHARED_SECRET_STAGING", base64.StdEncoding.EncodeToString(randomKey(t)))
	must(t, pol.ResolveSecrets())

	log := logrus.New()
	log.SetOutput(io.Discard)
	counter := &countingVerifier{}
	handler, err := New(Config{
		Location:          dischargeLocation,
		Policy:            pol,
		Verifier:          counter,
		Log:               log,
		RequestsPerSecond: 1,
		RequestBurst:      2,
		Now:               func() time.Time { return time.Unix(1_800_000_000, 0) },
	})
	must(t, err)

	post := func() int {
		req := httptest.NewRequest(http.MethodPost, tp.InitPath, bytes.NewReader([]byte(`{"ticket":"AAAA"}`)))
		req.Header.Set("Authorization", "Bearer whatever")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Code
	}

	for i := range 2 {
		if code := post(); code != http.StatusUnauthorized {
			t.Fatalf("burst request %d: status %d, want 401 from verification", i+1, code)
		}
	}
	if code := post(); code != http.StatusTooManyRequests {
		t.Errorf("status %d, want 429 once the burst is spent", code)
	}
	if got := counter.calls.Load(); got != 2 {
		t.Errorf("verification ran %d times, want 2: a limited request must not reach the issuer", got)
	}
}

// Health checks are not rate limited, so a stopped machine still reports ready.
func TestHealthzIsNotRateLimited(t *testing.T) {
	f := newFixtureWithLimits(t, 1, 1)
	for i := range 5 {
		rec := httptest.NewRecorder()
		f.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz %d: status %d", i+1, rec.Code)
		}
	}
}
