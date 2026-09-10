// Package server discharges Fly.io third-party caveats for GitHub Actions jobs
// that present an OIDC token matching the policy.
package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/macaroon"
	"github.com/superfly/macaroon/tp"

	"github.com/gz/fly-oidc-discharge/internal/policy"
)

// ClaimsVerifier authenticates a raw OIDC token and returns its claims.
type ClaimsVerifier interface {
	Claims(ctx context.Context, rawToken string) (map[string]string, error)
}

type Config struct {
	// Location must equal the URL given to `fly tokens 3p add --location`.
	Location string
	// Policy must have had ResolveSecrets called on it.
	Policy   *policy.Policy
	Verifier ClaimsVerifier
	Log      logrus.FieldLogger
	// RequestsPerSecond and RequestBurst bound the discharge endpoint. Zero
	// selects the defaults.
	RequestsPerSecond float64
	RequestBurst      float64
	// Now is swapped in tests to pin the ValidityWindow.
	Now func() time.Time
}

const (
	// A ticket is a few hundred bytes; anything larger is not a client of ours.
	maxRequestBytes = 16 << 10
	// Tolerates a Fly API clock slightly behind this service's.
	notBeforeSkew = 30 * time.Second
	// Caps a request that would otherwise wait on the issuer. The server's
	// read and write timeouts bound socket I/O, not handler work.
	requestTimeout = 30 * time.Second
	// Generous next to real traffic, which is a handful of requests per
	// deploy, and low enough to bound what a stranger can cost.
	defaultRequestsPerSecond = 5
	defaultRequestBurst      = 20
	// headerCredential tells the caller which credential it discharged, so a
	// job that picked up the wrong caveated token can say so in its log.
	headerCredential = "X-Discharge-Credential"
)

// claimsLogged are copied into every allow and deny log line.
var claimsLogged = []string{"sub", "repository", "ref", "environment", "event_name", "actor", "run_id", "job_workflow_ref"}

// credential is one policy credential plus the handler that discharges it.
type credential struct {
	*policy.Credential
	ttl     time.Duration
	handler http.Handler
}

type server struct {
	credentials []credential
	location    string
	verifier    ClaimsVerifier
	limiter     *rateLimiter
	log         logrus.FieldLogger
	now         func() time.Time
}

func New(cfg Config) (http.Handler, error) {
	switch {
	case cfg.Location == "":
		return nil, errors.New("location is required")
	case cfg.Policy == nil || cfg.Verifier == nil:
		return nil, errors.New("policy and verifier are required")
	}
	log := cfg.Log
	if log == nil {
		log = logrus.StandardLogger()
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	perSecond, burst := cfg.RequestsPerSecond, cfg.RequestBurst
	if perSecond <= 0 {
		perSecond = defaultRequestsPerSecond
	}
	if burst <= 0 {
		burst = defaultRequestBurst
	}

	s := &server{
		location: cfg.Location,
		verifier: cfg.Verifier,
		limiter:  newRateLimiter(perSecond, burst, now),
		log:      log,
		now:      now,
	}

	for i := range cfg.Policy.Credentials {
		source := &cfg.Policy.Credentials[i]
		if len(source.Secret) != 32 {
			return nil, fmt.Errorf("credential %q: secret is %d bytes, call ResolveSecrets first", source.Name, len(source.Secret))
		}
		thirdParty := &tp.TP{Location: cfg.Location, Key: source.Secret, Log: log}
		ttl := source.TTL(cfg.Policy.DefaultDischargeTTL)
		s.credentials = append(s.credentials, credential{
			Credential: source,
			ttl:        ttl,
			handler:    thirdParty.InitRequestMiddleware(s.discharge(thirdParty, ttl)),
		})
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("POST "+tp.InitPath, http.HandlerFunc(s.handleInit))
	return mux, nil
}

// handleInit authenticates the caller, works out which credential the ticket
// belongs to, and applies that credential's rules. Authentication comes first
// so an anonymous caller learns nothing about whether a ticket is valid.
func (s *server) handleInit(w http.ResponseWriter, r *http.Request) {
	// Before anything that costs: verification of an unknown key ID reaches
	// the issuer, and the caller is a stranger until its token is checked.
	if !s.limiter.allow() {
		s.log.Warn("deny: rate limited")
		w.Header().Set("Retry-After", "1")
		respondError(w, http.StatusTooManyRequests, "too many requests")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	r = r.WithContext(ctx)
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)

	claims, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	log := s.log.WithFields(logFields(claims))

	body, ticket, ok := s.readTicket(w, r, log)
	if !ok {
		return
	}
	chosen, ticketCaveats := s.selectCredential(ticket)
	if chosen == nil {
		log.WithField("location", s.location).Warn("deny: ticket matches no credential")
		respondError(w, http.StatusBadRequest,
			"ticket does not match this service's location or any configured shared secret")
		return
	}
	log = log.WithField("credential", chosen.Name)

	// A caveat sealed into the ticket is a condition the minter expects this
	// service to enforce. None are defined, so refusing beats ignoring them.
	if len(ticketCaveats) > 0 {
		log.WithField("caveats", len(ticketCaveats)).Warn("deny: ticket carries caveats")
		respondError(w, http.StatusBadRequest, "ticket carries caveats this service does not evaluate")
		return
	}
	rule, err := chosen.Match(claims)
	if err != nil {
		log.WithError(err).Warn("deny: policy")
		respondError(w, http.StatusForbidden,
			fmt.Sprintf("identity not allowed to discharge credential %q", chosen.Name))
		return
	}
	log.WithFields(logrus.Fields{"rule": rule.Name, "ttl": chosen.ttl.String()}).Info("allow")

	w.Header().Set(headerCredential, chosen.Name)
	r.Body = io.NopCloser(bytes.NewReader(body))
	chosen.handler.ServeHTTP(w, r)
}

func (s *server) authenticate(w http.ResponseWriter, r *http.Request) (map[string]string, bool) {
	rawToken, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing bearer token")
		return nil, false
	}
	claims, err := s.verifier.Claims(r.Context(), rawToken)
	if err != nil {
		s.log.WithError(err).Warn("deny: invalid OIDC token")
		respondError(w, http.StatusUnauthorized, "invalid OIDC token")
		return nil, false
	}
	return claims, true
}

// readTicket returns the raw body alongside the ticket, because tp's middleware
// parses the body again once a credential has been chosen.
func (s *server) readTicket(w http.ResponseWriter, r *http.Request, log logrus.FieldLogger) ([]byte, []byte, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.WithError(err).Warn("deny: unreadable request body")
		respondError(w, http.StatusBadRequest, "unreadable request body")
		return nil, nil, false
	}
	var request struct {
		Ticket []byte `json:"ticket"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		log.WithError(err).Warn("deny: malformed request body")
		respondError(w, http.StatusBadRequest, `body must be {"ticket": "<base64>"}`)
		return nil, nil, false
	}
	if len(request.Ticket) == 0 {
		respondError(w, http.StatusBadRequest, "no ticket in request")
		return nil, nil, false
	}
	return body, request.Ticket, true
}

// selectCredential finds the credential whose shared secret opens the ticket.
// The ticket names no credential, so the secret that decrypts it is the only
// evidence of which Fly token the caller is trying to use.
func (s *server) selectCredential(ticket []byte) (*credential, []macaroon.Caveat) {
	for i := range s.credentials {
		candidate := &s.credentials[i]
		caveats, _, err := macaroon.DischargeTicket(candidate.Secret, s.location, ticket)
		if err == nil {
			return candidate, caveats
		}
	}
	return nil, nil
}

func (s *server) discharge(thirdParty *tp.TP, ttl time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := s.now()
		thirdParty.RespondDischarge(w, r, &macaroon.ValidityWindow{
			NotBefore: now.Add(-notBeforeSkew).Unix(),
			NotAfter:  now.Add(ttl).Unix(),
		})
	})
}

// respondError writes the shape tp's client expects for a failure.
func respondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{message})
}

func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

func logFields(claims map[string]string) logrus.Fields {
	fields := make(logrus.Fields, len(claimsLogged))
	for _, name := range claimsLogged {
		if value, ok := claims[name]; ok {
			fields[name] = value
		}
	}
	return fields
}
