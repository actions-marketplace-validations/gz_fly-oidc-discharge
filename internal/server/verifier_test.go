package server

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// flakyIssuer serves discovery only once `up` is set, counting the attempts.
type flakyIssuer struct {
	url      string
	signer   jose.Signer
	up       atomic.Bool
	attempts atomic.Int32
}

func newFlakyIssuer(t *testing.T) *flakyIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)

	iss := &flakyIssuer{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		iss.attempts.Add(1)
		if !iss.up.Load() {
			http.Error(w, "issuer unavailable", http.StatusServiceUnavailable)
			return
		}
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

func (iss *flakyIssuer) token(t *testing.T, audience string) string {
	t.Helper()
	raw, err := jwt.Signed(iss.signer).Claims(jwt.Claims{
		Issuer:   iss.url,
		Subject:  "repo:acme/web:ref:refs/heads/main",
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).Claims(map[string]any{"repository": "acme/web"}).Serialize()
	must(t, err)
	return raw
}

// An issuer that is down at startup does not poison the verifier: the next
// token resolves it. A machine woken by Fly Proxy depends on this.
func TestVerifierRetriesAfterIssuerFailure(t *testing.T) {
	iss := newFlakyIssuer(t)
	verifier := NewVerifier(iss.url, dischargeLocation)

	if err := verifier.Warm(t.Context()); err == nil {
		t.Fatal("Warm should report an unreachable issuer")
	}
	if _, err := verifier.Claims(t.Context(), iss.token(t, dischargeLocation)); err == nil {
		t.Fatal("Claims should fail while the issuer is down")
	}

	iss.up.Store(true)
	claims, err := verifier.Claims(t.Context(), iss.token(t, dischargeLocation))
	if err != nil {
		t.Fatalf("Claims after the issuer recovered: %v", err)
	}
	if claims["repository"] != "acme/web" {
		t.Errorf("repository = %q", claims["repository"])
	}
}

// Once resolved, discovery is not repeated, and concurrent cold requests share
// a single attempt rather than one each.
func TestVerifierResolvesIssuerOnce(t *testing.T) {
	iss := newFlakyIssuer(t)
	iss.up.Store(true)
	verifier := NewVerifier(iss.url, dischargeLocation)
	token := iss.token(t, dischargeLocation)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := verifier.Claims(t.Context(), token); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if got := iss.attempts.Load(); got != 1 {
		t.Errorf("discovery ran %d times, want 1", got)
	}
}

// hangingIssuer serves discovery and JWKS but withholds the response for
// whichever endpoint is set to hang, until the test releases it.
type hangingIssuer struct {
	url     string
	signer  jose.Signer
	release chan struct{}
	hit     chan string
	hang    atomic.Value // "discovery" or "jwks"
}

func newHangingIssuer(t *testing.T, hang string) *hangingIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(t, err)

	iss := &hangingIssuer{
		release: make(chan struct{}),
		hit:     make(chan string, 16),
	}
	iss.hang.Store(hang)

	block := func(w http.ResponseWriter, r *http.Request, endpoint string) bool {
		select {
		case iss.hit <- endpoint:
		default:
		}
		if iss.hang.Load() != endpoint {
			return false
		}
		select {
		case <-iss.release:
			return false
		case <-r.Context().Done():
			return true
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		if block(w, r, "discovery") {
			return
		}
		must(t, json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                iss.url,
			"jwks_uri":                              iss.url + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		}))
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		if block(w, r, "jwks") {
			return
		}
		must(t, json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}}))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(func() {
		iss.releaseOnce()
		srv.Close()
	})
	iss.url = srv.URL

	iss.signer, err = jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "test").WithType("JWT"),
	)
	must(t, err)
	return iss
}

func (iss *hangingIssuer) releaseOnce() {
	select {
	case <-iss.release:
	default:
		close(iss.release)
	}
}

func (iss *hangingIssuer) token(t *testing.T, audience string) string {
	t.Helper()
	raw, err := jwt.Signed(iss.signer).Claims(jwt.Claims{
		Issuer:   iss.url,
		Subject:  "repo:acme/web:ref:refs/heads/main",
		Audience: jwt.Audience{audience},
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}).Claims(map[string]any{"repository": "acme/web"}).Serialize()
	must(t, err)
	return raw
}

// An issuer that accepts a request and never answers must not hold a caller
// past the HTTP timeout, for discovery or for the later key fetch.
func TestVerifierBoundsAStalledIssuer(t *testing.T) {
	for _, endpoint := range []string{"discovery", "jwks"} {
		t.Run(endpoint, func(t *testing.T) {
			iss := newHangingIssuer(t, endpoint)
			verifier := NewVerifier(iss.url, dischargeLocation, WithHTTPTimeout(200*time.Millisecond))

			done := make(chan error, 1)
			go func() { _, err := verifier.Claims(context.Background(), iss.token(t, dischargeLocation)); done <- err }()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("a stalled issuer must not verify a token")
				}
			case <-time.After(10 * time.Second):
				t.Fatal("Claims never returned: the outbound request is unbounded")
			}
		})
	}
}

// While one caller is stuck in discovery, another whose context has ended
// returns instead of queueing behind it.
func TestVerifierDoesNotPinWaitingCallers(t *testing.T) {
	iss := newHangingIssuer(t, "discovery")
	// Long timeout: the point is that waiters escape, not that the attempt ends.
	verifier := NewVerifier(iss.url, dischargeLocation, WithHTTPTimeout(30*time.Second))
	token := iss.token(t, dischargeLocation)

	stuck := make(chan error, 1)
	go func() { _, err := verifier.Claims(context.Background(), token); stuck <- err }()

	select {
	case <-iss.hit:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery was never attempted")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waiter := make(chan error, 1)
	go func() { _, err := verifier.Claims(ctx, token); waiter <- err }()

	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("waiter returned %v, want a context error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a waiting caller was pinned behind the stalled attempt")
	}

	iss.releaseOnce()
	<-stuck
}

// A stall is not sticky: once the issuer answers, the next token verifies.
func TestVerifierRecoversAfterAStall(t *testing.T) {
	iss := newHangingIssuer(t, "discovery")
	verifier := NewVerifier(iss.url, dischargeLocation, WithHTTPTimeout(200*time.Millisecond))
	token := iss.token(t, dischargeLocation)

	if _, err := verifier.Claims(context.Background(), token); err == nil {
		t.Fatal("expected the stalled issuer to fail")
	}
	iss.hang.Store("none")

	claims, err := verifier.Claims(context.Background(), token)
	if err != nil {
		t.Fatalf("Claims after recovery: %v", err)
	}
	if claims["repository"] != "acme/web" {
		t.Errorf("repository = %q", claims["repository"])
	}
}
