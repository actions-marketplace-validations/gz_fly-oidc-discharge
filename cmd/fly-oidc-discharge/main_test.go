package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// selfSignedPEM returns a certificate and key for localhost, plus a pool that
// trusts it, so a test can complete a real handshake.
func selfSignedPEM(t *testing.T) (certPEM, keyPEM string, pool *x509.CertPool) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))

	pool = x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(certPEM)) {
		t.Fatal("could not trust the generated certificate")
	}
	return certPEM, keyPEM, pool
}

// A configured key pair produces a real HTTPS listener that a client verifying
// the certificate can talk to.
func TestServesTLSWhenConfigured(t *testing.T) {
	certPEM, keyPEM, pool := selfSignedPEM(t)
	policyPath := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(policyPath, []byte(fmtPolicy("prod")), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("OIDC_DISCHARGE_LOCATION", "https://localhost")
	t.Setenv("POLICY_FILE", policyPath)
	t.Setenv("SHARED_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("TLS_CERT", certPEM)
	t.Setenv("TLS_PRIVATE_KEY", keyPEM)
	t.Setenv("LISTEN_ADDR", "127.0.0.1:0")

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.hasTLS() {
		t.Fatal("hasTLS is false with both halves set")
	}

	certificate, err := tls.X509KeyPair([]byte(cfg.tlsCert), []byte(cfg.tlsKey))
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}}}
	resp, err := client.Get("https://" + listener.Addr().String() + "/healthz")
	if err != nil {
		t.Fatalf("verified HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || !resp.TLS.HandshakeComplete {
		t.Error("the connection did not complete a TLS handshake")
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status %d", resp.StatusCode)
	}
}

// Half a key pair is a deployment mistake, not a reason to serve plain HTTP.
func TestConfigRejectsHalfATLSPair(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedPEM(t)
	for name, pair := range map[string][2]string{
		"certificate only": {certPEM, ""},
		"key only":         {"", keyPEM},
	} {
		t.Setenv("OIDC_DISCHARGE_LOCATION", "https://discharge.example.com")
		t.Setenv("TLS_CERT", pair[0])
		t.Setenv("TLS_PRIVATE_KEY", pair[1])
		_, err := configFromEnv()
		if err == nil || !strings.Contains(err.Error(), "both TLS_CERT and TLS_PRIVATE_KEY") {
			t.Errorf("%s: err = %v, want a complaint about the pair", name, err)
		}
	}
}

// Serving TLS while advertising an http:// location would hand callers a
// location they cannot reach.
func TestConfigRejectsPlainLocationWithTLS(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedPEM(t)
	t.Setenv("OIDC_DISCHARGE_LOCATION", "http://discharge.example.com")
	t.Setenv("TLS_CERT", certPEM)
	t.Setenv("TLS_PRIVATE_KEY", keyPEM)
	if _, err := configFromEnv(); err == nil {
		t.Fatal("an http:// location was accepted while serving TLS")
	}
}

// Without a key pair the service still serves plain HTTP, which local runs and
// the container example rely on.
func TestConfigAllowsPlainHTTP(t *testing.T) {
	t.Setenv("OIDC_DISCHARGE_LOCATION", "http://127.0.0.1:8080")
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_PRIVATE_KEY", "")
	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.hasTLS() {
		t.Error("hasTLS is true with neither half set")
	}
}

// The _FILE variants let a deployment mount the pair instead of passing PEM
// through the environment.
func TestTLSFromFiles(t *testing.T) {
	certPEM, keyPEM, _ := selfSignedPEM(t)
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("OIDC_DISCHARGE_LOCATION", "https://discharge.example.com")
	t.Setenv("TLS_CERT", "")
	t.Setenv("TLS_PRIVATE_KEY", "")
	t.Setenv("TLS_CERT_FILE", certPath)
	t.Setenv("TLS_PRIVATE_KEY_FILE", keyPath)

	cfg, err := configFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.hasTLS() {
		t.Fatal("hasTLS is false with both files set")
	}
	if _, err := tls.X509KeyPair([]byte(cfg.tlsCert), []byte(cfg.tlsKey)); err != nil {
		t.Errorf("the file-loaded pair does not parse: %v", err)
	}
}
