// Command fly-oidc-discharge issues Fly.io third-party caveat discharges to
// GitHub Actions jobs that prove their identity with an OIDC token.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/gz/fly-oidc-discharge/internal/policy"
	"github.com/gz/fly-oidc-discharge/internal/server"
)

const (
	defaultIssuer     = "https://token.actions.githubusercontent.com"
	defaultListenAddr = ":8080"
	defaultPolicyFile = "/etc/fly-oidc-discharge/policy.yaml"
	shutdownTimeout   = 10 * time.Second
	issuerWarmTimeout = 5 * time.Second
)

type config struct {
	listenAddr string
	location   string
	issuer     string
	audience   string
	// tlsCert and tlsKey hold PEM content. Both or neither.
	tlsCert string
	tlsKey  string
	// policyFile is ignored when policyInline is set.
	policyFile   string
	policyInline string
}

func main() {
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	if err := run(log); err != nil {
		log.Fatal(err)
	}
}

func run(log *logrus.Logger) error {
	cfg, err := configFromEnv()
	if err != nil {
		return err
	}
	pol, source, err := cfg.loadPolicy()
	if err != nil {
		return err
	}
	if err := pol.ResolveSecrets(); err != nil {
		return err
	}
	for _, warning := range pol.Warnings() {
		log.Warn(warning)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// A failure here is not fatal: the issuer is resolved again on the first
	// token, so a machine woken by Fly Proxy still serves once GitHub answers.
	verifier := server.NewVerifier(cfg.issuer, cfg.audience)
	warmCtx, cancelWarm := context.WithTimeout(ctx, issuerWarmTimeout)
	defer cancelWarm()
	if err := verifier.Warm(warmCtx); err != nil {
		log.WithError(err).Warn("issuer not resolved at startup, retrying on first request")
	}

	handler, err := server.New(server.Config{
		Location: cfg.location,
		Policy:   pol,
		Verifier: verifier,
		Log:      log,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:              cfg.listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	scheme := "http"
	if cfg.hasTLS() {
		certificate, err := tls.X509KeyPair([]byte(cfg.tlsCert), []byte(cfg.tlsKey))
		if err != nil {
			return fmt.Errorf("load TLS certificate: %w", err)
		}
		httpServer.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
		scheme = "https"
	}

	serveErr := make(chan error, 1)
	go func() {
		if cfg.hasTLS() {
			// The key pair is already parsed into TLSConfig.
			serveErr <- httpServer.ListenAndServeTLS("", "")
			return
		}
		serveErr <- httpServer.ListenAndServe()
	}()
	for _, credential := range pol.Credentials {
		log.WithFields(logrus.Fields{
			"credential": credential.Name,
			"rules":      len(credential.Rules),
			"ttl":        credential.TTL(pol.DefaultDischargeTTL).String(),
		}).Info("credential loaded")
	}
	log.WithFields(logrus.Fields{
		"addr":        cfg.listenAddr,
		"scheme":      scheme,
		"policy":      source,
		"location":    cfg.location,
		"issuer":      cfg.issuer,
		"audience":    cfg.audience,
		"credentials": len(pol.Credentials),
	}).Info("listening")

	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return httpServer.Shutdown(shutdownCtx)
}

func configFromEnv() (*config, error) {
	var missing []string
	require := func(name string) string {
		value := os.Getenv(name)
		if value == "" {
			missing = append(missing, name)
		}
		return value
	}

	cfg := &config{
		listenAddr:   envOr("LISTEN_ADDR", defaultListenAddr),
		location:     require("OIDC_DISCHARGE_LOCATION"),
		issuer:       envOr("OIDC_ISSUER", defaultIssuer),
		policyFile:   envOr("POLICY_FILE", defaultPolicyFile),
		policyInline: os.Getenv("POLICY_YAML"),
	}
	cfg.audience = envOr("OIDC_AUDIENCE", cfg.location)
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment: %s", strings.Join(missing, ", "))
	}

	var err error
	if cfg.tlsCert, err = pemFromEnv("TLS_CERT"); err != nil {
		return nil, err
	}
	if cfg.tlsKey, err = pemFromEnv("TLS_PRIVATE_KEY"); err != nil {
		return nil, err
	}
	// Half a key pair is a deployment mistake, and falling back to plain HTTP
	// would silently downgrade a caller expecting https.
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		return nil, errors.New("set both TLS_CERT and TLS_PRIVATE_KEY, or neither")
	}
	if cfg.hasTLS() && strings.HasPrefix(cfg.location, "http://") {
		return nil, fmt.Errorf("serving TLS but OIDC_DISCHARGE_LOCATION is %s: the caveat location must be the URL callers use", cfg.location)
	}
	return cfg, nil
}

func (c *config) hasTLS() bool { return c.tlsCert != "" && c.tlsKey != "" }

// pemFromEnv reads PEM content from NAME, or from the file named by NAME_FILE.
func pemFromEnv(name string) (string, error) {
	if path := os.Getenv(name + "_FILE"); path != "" {
		pem, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s_FILE: %w", name, err)
		}
		return string(pem), nil
	}
	return os.Getenv(name), nil
}

// loadPolicy reads the policy from POLICY_YAML when set, so the published
// image can be deployed with no file mounted, and reports which source it used.
func (c *config) loadPolicy() (*policy.Policy, string, error) {
	if c.policyInline != "" {
		pol, err := policy.Parse([]byte(c.policyInline))
		return pol, "$POLICY_YAML", err
	}
	pol, err := policy.Load(c.policyFile)
	return pol, c.policyFile, err
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
