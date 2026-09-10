package server

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// go-oidc issues discovery and JWKS requests with http.DefaultClient, which has
// no timeout, unless it is handed a client. It also fetches keys on a
// background context of its own, so a deadline on the caller's context does not
// reach them. A client timeout is what bounds both.
const defaultOIDCHTTPTimeout = 10 * time.Second

// Verifier checks GitHub Actions ID tokens against the issuer's published keys.
//
// Discovery is deferred to the first token so that a machine woken by Fly Proxy
// serves requests without a network round trip on its startup path, and so a
// brief issuer outage cannot turn into a crash loop. A failed attempt is not
// cached, so the next request retries.
type Verifier struct {
	issuer   string
	audience string
	client   *http.Client

	// resolving has capacity one and serves as a mutex a caller can abandon
	// when its own context ends, so a stalled issuer cannot pin every request.
	resolving chan struct{}
	resolved  atomic.Pointer[oidc.IDTokenVerifier]
}

type VerifierOption func(*Verifier)

// WithHTTPTimeout bounds each discovery and JWKS request.
func WithHTTPTimeout(timeout time.Duration) VerifierOption {
	return func(v *Verifier) { v.client.Timeout = timeout }
}

func NewVerifier(issuer, audience string, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		issuer:    issuer,
		audience:  audience,
		client:    &http.Client{Timeout: defaultOIDCHTTPTimeout},
		resolving: make(chan struct{}, 1),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Warm resolves the issuer ahead of the first request. Callers treat a failure
// as a warning: Claims will try again.
func (v *Verifier) Warm(ctx context.Context) error {
	_, err := v.resolve(ctx)
	return err
}

// resolve returns the cached verifier without locking, and otherwise lets one
// caller at a time attempt discovery while the rest wait or give up.
func (v *Verifier) resolve(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	if resolved := v.resolved.Load(); resolved != nil {
		return resolved, nil
	}

	select {
	case v.resolving <- struct{}{}:
		defer func() { <-v.resolving }()
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting to resolve OIDC issuer %s: %w", v.issuer, ctx.Err())
	}

	// Another caller may have finished while this one waited.
	if resolved := v.resolved.Load(); resolved != nil {
		return resolved, nil
	}

	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, v.client), v.issuer)
	if err != nil {
		return nil, fmt.Errorf("discover OIDC issuer %s: %w", v.issuer, err)
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: v.audience})
	v.resolved.Store(verifier)
	return verifier, nil
}

// Claims verifies rawToken and flattens its claims to strings. GitHub emits
// strings and booleans; booleans become "true"/"false" so a policy can require,
// for example, ref_protected: "true". Numbers and arrays are dropped because
// none of them identify the caller.
func (v *Verifier) Claims(ctx context.Context, rawToken string) (map[string]string, error) {
	idTokens, err := v.resolve(ctx)
	if err != nil {
		return nil, err
	}
	idToken, err := idTokens.Verify(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := idToken.Claims(&raw); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	claims := make(map[string]string, len(raw))
	for name, value := range raw {
		switch typed := value.(type) {
		case string:
			claims[name] = typed
		case bool:
			claims[name] = strconv.FormatBool(typed)
		}
	}
	return claims, nil
}
