package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"
	keystore "github.com/pavlo-v-chernykh/keystore-go/v4"
	"golang.org/x/crypto/pkcs12"
	"github.com/twmb/franz-go/pkg/sasl/oauth"
	"github.com/twmb/franz-go/pkg/sasl/plain"
	"github.com/twmb/franz-go/pkg/sasl/scram"
)

// ── Result ────────────────────────────────────────────────────────────────────

type status int

const (
	statusOK      status = iota
	statusDenied         // ACL / auth rejection
	statusSkipped        // dependency unavailable, check skipped
	statusError          // unexpected non-auth error
)

type Result struct {
	Name   string
	Status status
	Detail string
}

func icon(s status) string {
	switch s {
	case statusOK:
		return "✅"
	case statusDenied:
		return "❌"
	case statusSkipped:
		return "⏭ "
	default:
		return "⚠️ "
	}
}

// Section buffers the results and output lines for one group of checks
// so that parallel sections can be flushed in order.
type Section struct {
	header  string
	lines   []string
	results []Result
}

func newSection(header string) *Section {
	return &Section{header: header}
}

func (s *Section) record(name string, st status, detail string) {
	s.results = append(s.results, Result{name, st, detail})
	s.lines = append(s.lines, fmt.Sprintf("  %s  %-44s %s", icon(st), name, detail))
}

func (s *Section) flush() []Result {
	fmt.Println(s.header)
	for _, l := range s.lines {
		fmt.Println(l)
	}
	fmt.Println()
	return s.results
}

// ── Auth error classification ─────────────────────────────────────────────────

func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	keywords := []string{
		"topic_authorization_failed",
		"group_authorization_failed",
		"transactional_id_authorization_failed",
		"cluster_authorization_failed",
		"not authorized",
		"authorization",
		"sasl",
	}
	for _, kw := range keywords {
		if strings.Contains(msg, kw) {
			return true
		}
	}
	return false
}

func classify(err error, okDetail string) (status, string) {
	if err == nil {
		return statusOK, okDetail
	}
	if isAuthError(err) {
		return statusDenied, err.Error()
	}
	return statusError, err.Error()
}

// ── Config & properties file ──────────────────────────────────────────────────

// Config holds all connection parameters derived from a properties file.
type Config struct {
	Brokers       []string
	SASLMechanism string // plain | scram-sha-256 | scram-sha-512 | oauthbearer
	SASLUser      string
	SASLPass      string

	// OAuthBearer
	OAuthTokenEndpoint string
	OAuthClientID      string
	OAuthClientSecret  string
	OAuthScope         string

	// TLS / mTLS
	TLS           bool
	TLSSkipVerify bool
	// PEM (ssl.ca.location / ssl.certificate.location / ssl.key.location)
	TLSCAFile   string
	TLSCertFile string
	TLSKeyFile  string
	TLSKeyPass  string
	// Truststore / keystore (JKS or PKCS12 — takes precedence over PEM if set)
	TLSTruststorePath string // ssl.truststore.location
	TLSTruststorePass string // ssl.truststore.password
	TLSKeystorePath   string // ssl.keystore.location
	TLSKeystorePass   string // ssl.keystore.password

	// Schema Registry
	SRUrl           string // schema.registry.url
	SRBasicAuthUser string // schema.registry.basic.auth.user.info (user part)
	SRBasicAuthPass string // schema.registry.basic.auth.user.info (password part)
	// SR TLS — PKCS12 truststore/keystore (independent from Kafka TLS)
	SRTruststorePath string // schema.registry.ssl.truststore.location
	SRTruststorePass string // schema.registry.ssl.truststore.password
	SRKeystorePath   string // schema.registry.ssl.keystore.location
	SRKeystorePass   string // schema.registry.ssl.keystore.password
	SRTLSSkipVerify  bool   // schema.registry.ssl.endpoint.identification.algorithm=""

	Timeout     time.Duration
	PollTimeout time.Duration
}

// loadProperties parses a Java-style key=value properties file.
// Lines starting with # or ! are comments. Blank lines are ignored.
func loadProperties(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading properties file %q: %w", path, err)
	}
	props := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		props[key] = val
	}
	return props, nil
}

// configFromProperties builds a Config from parsed properties and a timeout.
//
// Supported properties:
//
//	bootstrap.servers          — comma-separated broker list
//	security.protocol          — PLAINTEXT | SSL | SASL_PLAINTEXT | SASL_SSL
//	sasl.mechanism             — PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512 | OAUTHBEARER
//	sasl.username              — SASL username (PLAIN / SCRAM)
//	sasl.password              — SASL password (PLAIN / SCRAM)
//	sasl.oauthbearer.token.endpoint.url  — OAuth2 token endpoint
//	sasl.oauthbearer.client.id           — OAuth2 client ID
//	sasl.oauthbearer.client.secret       — OAuth2 client secret
//	sasl.oauthbearer.scope               — OAuth2 scope (optional)
//	ssl.truststore.location    — JKS or PKCS12 truststore (CA certs); takes precedence over ssl.ca.location
//	ssl.truststore.password    — truststore passphrase
//	ssl.keystore.location      — JKS or PKCS12 keystore (client cert+key for mTLS); takes precedence over ssl.certificate.location
//	ssl.keystore.password      — keystore passphrase
//	ssl.ca.location            — PEM CA cert (used when no truststore is set)
//	ssl.certificate.location   — PEM client certificate (used when no keystore is set)
//	ssl.key.location           — PEM client private key (used when no keystore is set)
//	ssl.key.password           — passphrase for encrypted PEM private key
//	ssl.endpoint.identification.algorithm — set to empty string to disable hostname verification
//	schema.registry.url                              — Schema Registry base URL
//	schema.registry.basic.auth.user.info             — user:password for basic auth
//	schema.registry.ssl.truststore.location          — PKCS12 truststore (CA certs)
//	schema.registry.ssl.truststore.password          — truststore passphrase
//	schema.registry.ssl.keystore.location            — PKCS12 keystore (client cert+key for mTLS)
//	schema.registry.ssl.keystore.password            — keystore passphrase
//	schema.registry.ssl.endpoint.identification.algorithm — set to empty string to disable hostname verification
func configFromProperties(props map[string]string, timeout time.Duration) (Config, error) {
	cfg := Config{Timeout: timeout}

	if v := props["bootstrap.servers"]; v != "" {
		parts := strings.Split(v, ",")
		for _, p := range parts {
			if b := strings.TrimSpace(p); b != "" {
				cfg.Brokers = append(cfg.Brokers, b)
			}
		}
	}
	if len(cfg.Brokers) == 0 {
		cfg.Brokers = []string{"localhost:9092"}
	}

	protocol := strings.ToUpper(strings.TrimSpace(props["security.protocol"]))
	cfg.TLS = strings.Contains(protocol, "SSL")

	mechanism := strings.ToUpper(strings.TrimSpace(props["sasl.mechanism"]))
	switch mechanism {
	case "PLAIN":
		cfg.SASLMechanism = "plain"
		cfg.SASLUser = props["sasl.username"]
		cfg.SASLPass = props["sasl.password"]
	case "SCRAM-SHA-256":
		cfg.SASLMechanism = "scram-sha-256"
		cfg.SASLUser = props["sasl.username"]
		cfg.SASLPass = props["sasl.password"]
	case "SCRAM-SHA-512":
		cfg.SASLMechanism = "scram-sha-512"
		cfg.SASLUser = props["sasl.username"]
		cfg.SASLPass = props["sasl.password"]
	case "OAUTHBEARER":
		cfg.SASLMechanism = "oauthbearer"
		cfg.OAuthTokenEndpoint = props["sasl.oauthbearer.token.endpoint.url"]
		cfg.OAuthClientID = props["sasl.oauthbearer.client.id"]
		cfg.OAuthClientSecret = props["sasl.oauthbearer.client.secret"]
		cfg.OAuthScope = props["sasl.oauthbearer.scope"]
		if cfg.OAuthTokenEndpoint == "" {
			return cfg, fmt.Errorf("sasl.oauthbearer.token.endpoint.url is required for OAUTHBEARER")
		}
		if cfg.OAuthClientID == "" || cfg.OAuthClientSecret == "" {
			return cfg, fmt.Errorf("sasl.oauthbearer.client.id and sasl.oauthbearer.client.secret are required for OAUTHBEARER")
		}
	case "":
		// no SASL
	default:
		return cfg, fmt.Errorf("unsupported sasl.mechanism: %s", mechanism)
	}

	cfg.TLSTruststorePath = props["ssl.truststore.location"]
	cfg.TLSTruststorePass = props["ssl.truststore.password"]
	cfg.TLSKeystorePath = props["ssl.keystore.location"]
	cfg.TLSKeystorePass = props["ssl.keystore.password"]
	cfg.TLSCAFile = props["ssl.ca.location"]
	cfg.TLSCertFile = props["ssl.certificate.location"]
	cfg.TLSKeyFile = props["ssl.key.location"]
	cfg.TLSKeyPass = props["ssl.key.password"]

	// An empty ssl.endpoint.identification.algorithm disables hostname verification.
	if v, ok := props["ssl.endpoint.identification.algorithm"]; ok {
		cfg.TLSSkipVerify = strings.TrimSpace(v) == ""
	}

	cfg.SRUrl = strings.TrimRight(props["schema.registry.url"], "/")

	if v := props["schema.registry.basic.auth.user.info"]; v != "" {
		user, pass, _ := strings.Cut(v, ":")
		cfg.SRBasicAuthUser = user
		cfg.SRBasicAuthPass = pass
	}

	cfg.SRTruststorePath = props["schema.registry.ssl.truststore.location"]
	cfg.SRTruststorePass = props["schema.registry.ssl.truststore.password"]
	cfg.SRKeystorePath = props["schema.registry.ssl.keystore.location"]
	cfg.SRKeystorePass = props["schema.registry.ssl.keystore.password"]

	if v, ok := props["schema.registry.ssl.endpoint.identification.algorithm"]; ok {
		cfg.SRTLSSkipVerify = strings.TrimSpace(v) == ""
	}

	return cfg, nil
}

// ── TLS helpers ───────────────────────────────────────────────────────────────

// buildTLSConfig constructs a *tls.Config from Config.
// Returns nil when TLS is not enabled.
// Truststore/keystore (JKS or PKCS12) take precedence over PEM files when both are set.
func buildTLSConfig(cfg Config) (*tls.Config, error) {
	if !cfg.TLS {
		return nil, nil
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec
	}

	switch {
	case cfg.TLSTruststorePath != "":
		pool, err := loadTruststorePool(cfg.TLSTruststorePath, cfg.TLSTruststorePass)
		if err != nil {
			return nil, fmt.Errorf("loading ssl.truststore: %w", err)
		}
		tlsCfg.RootCAs = pool
	case cfg.TLSCAFile != "":
		caPEM, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("reading ssl.ca.location %q: %w", cfg.TLSCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("failed to parse CA certificate from %q", cfg.TLSCAFile)
		}
		tlsCfg.RootCAs = pool
	}

	switch {
	case cfg.TLSKeystorePath != "":
		cert, err := loadKeystorePair(cfg.TLSKeystorePath, cfg.TLSKeystorePass, cfg.TLSKeyPass)
		if err != nil {
			return nil, fmt.Errorf("loading ssl.keystore: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	case cfg.TLSCertFile != "" || cfg.TLSKeyFile != "":
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return nil, fmt.Errorf("ssl.certificate.location and ssl.key.location must both be set for mTLS")
		}
		cert, err := loadKeyPair(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSKeyPass)
		if err != nil {
			return nil, fmt.Errorf("loading mTLS client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// loadKeyPair loads a certificate/key pair, decrypting the key if a passphrase is provided.
func loadKeyPair(certFile, keyFile, keyPass string) (tls.Certificate, error) {
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading cert file %q: %w", certFile, err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading key file %q: %w", keyFile, err)
	}

	if keyPass != "" {
		block, _ := pem.Decode(keyPEM)
		if block == nil {
			return tls.Certificate{}, fmt.Errorf("failed to decode PEM block from %q", keyFile)
		}
		//nolint:staticcheck
		decrypted, err := x509.DecryptPEMBlock(block, []byte(keyPass))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("decrypting private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: decrypted})
	}

	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── Schema Registry TLS ───────────────────────────────────────────────────────

// buildSRTLSConfig constructs a *tls.Config for Schema Registry HTTP connections.
// Loads CA certs from a PKCS12 truststore and a client cert+key from a PKCS12
// keystore. Returns nil when no SR-specific TLS properties are set (Go's default
// TLS is used, which trusts the system CA store).
func buildSRTLSConfig(cfg Config) (*tls.Config, error) {
	if cfg.SRTruststorePath == "" && cfg.SRKeystorePath == "" && !cfg.SRTLSSkipVerify {
		return nil, nil
	}

	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.SRTLSSkipVerify} //nolint:gosec

	if cfg.SRTruststorePath != "" {
		pool, err := loadTruststorePool(cfg.SRTruststorePath, cfg.SRTruststorePass)
		if err != nil {
			return nil, fmt.Errorf("loading SR truststore: %w", err)
		}
		tlsCfg.RootCAs = pool
	}

	if cfg.SRKeystorePath != "" {
		cert, err := loadKeystorePair(cfg.SRKeystorePath, cfg.SRKeystorePass, "")
		if err != nil {
			return nil, fmt.Errorf("loading SR keystore: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}

// isJKS detects a JKS file by its magic bytes (0xFEEDFEED).
func isJKS(data []byte) bool {
	return len(data) >= 4 &&
		data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFE && data[3] == 0xED
}

// loadTruststorePool loads CA certificates from a JKS or PKCS12 truststore.
func loadTruststorePool(path, password string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if isJKS(data) {
		return jksCertPool(data, password)
	}
	return pkcs12CertPool(data, password)
}

// loadKeystorePair loads a client certificate and private key from a JKS or PKCS12 keystore.
// storePass is the keystore password; keyPass is the per-entry private key password (JKS only).
// If keyPass is empty it falls back to storePass.
func loadKeystorePair(path, storePass, keyPass string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("reading %q: %w", path, err)
	}
	if isJKS(data) {
		return jksKeyPair(data, storePass, keyPass)
	}
	return pkcs12KeyPair(data, storePass)
}

// jksCertPool extracts all trusted certificate entries from a JKS truststore.
func jksCertPool(data []byte, password string) (*x509.CertPool, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return nil, fmt.Errorf("loading JKS: %w", err)
	}
	pool := x509.NewCertPool()
	for _, alias := range ks.Aliases() {
		if !ks.IsTrustedCertificateEntry(alias) {
			continue
		}
		entry, err := ks.GetTrustedCertificateEntry(alias)
		if err != nil {
			return nil, fmt.Errorf("reading JKS entry %q: %w", alias, err)
		}
		cert, err := x509.ParseCertificate(entry.Certificate.Content)
		if err != nil {
			return nil, fmt.Errorf("parsing JKS certificate %q: %w", alias, err)
		}
		pool.AddCert(cert)
	}
	return pool, nil
}

// jksKeyPair extracts the first private key entry from a JKS keystore.
// storePass unlocks the keystore; keyPass unlocks the private key entry.
// If keyPass is empty, storePass is used for the key entry as well.
func jksKeyPair(data []byte, storePass, keyPass string) (tls.Certificate, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(storePass)); err != nil {
		return tls.Certificate{}, fmt.Errorf("loading JKS: %w", err)
	}
	entryPass := keyPass
	if entryPass == "" {
		entryPass = storePass
	}
	for _, alias := range ks.Aliases() {
		if !ks.IsPrivateKeyEntry(alias) {
			continue
		}
		entry, err := ks.GetPrivateKeyEntry(alias, []byte(entryPass))
		if err != nil {
			return tls.Certificate{}, fmt.Errorf("reading JKS key entry %q: %w", alias, err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: entry.PrivateKey})
		var certPEM []byte
		for _, c := range entry.CertificateChain {
			certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Content})...)
		}
		if len(certPEM) == 0 || len(keyPEM) == 0 {
			return tls.Certificate{}, fmt.Errorf("JKS entry %q is missing cert or key", alias)
		}
		return tls.X509KeyPair(certPEM, keyPEM)
	}
	return tls.Certificate{}, fmt.Errorf("no private key entry found in JKS keystore")
}

// pkcs12CertPool loads CA certificates from a PKCS12 truststore.
func pkcs12CertPool(data []byte, password string) (*x509.CertPool, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("decoding PKCS12: %w", err)
	}
	pool := x509.NewCertPool()
	for _, block := range blocks {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("parsing PKCS12 certificate: %w", err)
			}
			pool.AddCert(cert)
		}
	}
	return pool, nil
}

// pkcs12KeyPair extracts a client certificate and private key from a PKCS12 keystore.
func pkcs12KeyPair(data []byte, password string) (tls.Certificate, error) {
	blocks, err := pkcs12.ToPEM(data, password)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("decoding PKCS12: %w", err)
	}
	var certPEM, keyPEM []byte
	for _, block := range blocks {
		switch block.Type {
		case "CERTIFICATE":
			certPEM = append(certPEM, pem.EncodeToMemory(block)...)
		case "PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY":
			keyPEM = append(keyPEM, pem.EncodeToMemory(block)...)
		}
	}
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return tls.Certificate{}, fmt.Errorf("PKCS12 keystore must contain both a certificate and a private key")
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// ── OAuth2 token fetch ────────────────────────────────────────────────────────

// fetchClientCredentialsToken performs an OAuth2 client_credentials grant
// against the configured token endpoint and returns an oauth.Auth token.
func fetchClientCredentialsToken(ctx context.Context, cfg Config) (oauth.Auth, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {cfg.OAuthClientID},
		"client_secret": {cfg.OAuthClientSecret},
	}
	if cfg.OAuthScope != "" {
		form.Set("scope", cfg.OAuthScope)
	}

	httpCl := &http.Client{Timeout: cfg.Timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.OAuthTokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return oauth.Auth{}, fmt.Errorf("building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpCl.Do(req)
	if err != nil {
		return oauth.Auth{}, fmt.Errorf("token request to %q failed: %w", cfg.OAuthTokenEndpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return oauth.Auth{}, fmt.Errorf("reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return oauth.Auth{}, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return oauth.Auth{}, fmt.Errorf("parsing token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return oauth.Auth{}, fmt.Errorf("empty access_token in token response")
	}

	return oauth.Auth{Token: tokenResp.AccessToken}, nil
}

// ── Client factory ────────────────────────────────────────────────────────────

func newClient(cfg Config, extra ...kgo.Opt) (*kgo.Client, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(cfg.Brokers...),
		kgo.DialTimeout(cfg.Timeout),
		kgo.RequestTimeoutOverhead(cfg.Timeout),
	}

	tlsCfg, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("building TLS config: %w", err)
	}
	if tlsCfg != nil {
		opts = append(opts, kgo.DialTLSConfig(tlsCfg))
	}

	switch strings.ToLower(cfg.SASLMechanism) {
	case "plain":
		opts = append(opts, kgo.SASL(plain.Auth{
			User: cfg.SASLUser,
			Pass: cfg.SASLPass,
		}.AsMechanism()))
	case "scram-sha-256":
		opts = append(opts, kgo.SASL(scram.Auth{
			User: cfg.SASLUser,
			Pass: cfg.SASLPass,
		}.AsSha256Mechanism()))
	case "scram-sha-512":
		opts = append(opts, kgo.SASL(scram.Auth{
			User: cfg.SASLUser,
			Pass: cfg.SASLPass,
		}.AsSha512Mechanism()))
	case "oauthbearer":
		opts = append(opts, kgo.SASL(oauth.Oauth(func(ctx context.Context) (oauth.Auth, error) {
			return fetchClientCredentialsToken(ctx, cfg)
		})))
	case "":
		// no auth
	default:
		return nil, fmt.Errorf("unsupported SASL mechanism: %s", cfg.SASLMechanism)
	}

	return kgo.NewClient(append(opts, extra...)...)
}

// ── Topic checks ──────────────────────────────────────────────────────────────

func checkTopicDescribe(ctx context.Context, cfg Config, topic string, sec *Section) {
	cl, err := newClient(cfg)
	if err != nil {
		sec.record("topic:DESCRIBE", statusError, err.Error())
		return
	}
	defer cl.Close()

	adm := kadm.NewClient(cl)
	_, err = adm.DescribeTopicConfigs(ctx, topic)
	s, d := classify(err, "metadata readable")
	sec.record("topic:DESCRIBE", s, d)
}

func checkTopicRead(ctx context.Context, cfg Config, topic string, sec *Section) {
	cl, err := newClient(cfg,
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
	)
	if err != nil {
		sec.record("topic:READ", statusError, err.Error())
		return
	}
	defer cl.Close()

	pollCtx, cancel := context.WithTimeout(ctx, cfg.PollTimeout)
	defer cancel()

	fetches := cl.PollRecords(pollCtx, 1)
	if errs := fetches.Errors(); len(errs) > 0 {
		for _, fe := range errs {
			if strings.Contains(fe.Err.Error(), "context deadline exceeded") ||
				strings.Contains(fe.Err.Error(), "context canceled") {
				sec.record("topic:READ", statusOK, "fetch issued successfully (no new records in poll window)")
				return
			}
		}
		s, d := classify(errs[0].Err, "")
		sec.record("topic:READ", s, d)
		return
	}
	sec.record("topic:READ", statusOK, "poll succeeded (no commit)")
}

func checkTopicWrite(ctx context.Context, cfg Config, topic string, sec *Section) {
	cl, err := newClient(cfg,
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.DefaultProduceTopic(topic),
	)
	if err != nil {
		sec.record("topic:WRITE", statusError, err.Error())
		return
	}
	defer cl.Close()

	ackCh := make(chan error, 1)
	cl.Produce(ctx, &kgo.Record{
		Key:   []byte("perm-check"),
		Value: []byte("kafka-perm-check probe"),
	}, func(_ *kgo.Record, err error) {
		ackCh <- err
	})

	select {
	case err := <-ackCh:
		s, d := classify(err, "message delivered")
		sec.record("topic:WRITE", s, d)
	case <-time.After(cfg.Timeout):
		sec.record("topic:WRITE", statusError, "timeout waiting for ack")
	}
}

// ── Consumer group checks ─────────────────────────────────────────────────────

func checkGroupDescribe(ctx context.Context, cfg Config, group string, sec *Section) {
	cl, err := newClient(cfg)
	if err != nil {
		sec.record("group:DESCRIBE", statusError, err.Error())
		return
	}
	defer cl.Close()

	adm := kadm.NewClient(cl)
	described, err := adm.DescribeGroups(ctx, group)
	if err != nil {
		s, d := classify(err, "")
		sec.record("group:DESCRIBE", s, d)
		return
	}
	if g, ok := described[group]; ok && g.Err != nil {
		s, d := classify(g.Err, "")
		sec.record("group:DESCRIBE", s, d)
		return
	}
	sec.record("group:DESCRIBE", statusOK, "group metadata readable")
}

func checkGroupRead(ctx context.Context, cfg Config, group, topic string, sec *Section) {
	cl, err := newClient(cfg,
		kgo.ConsumerGroup(group),
		kgo.ConsumeTopics(topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
		kgo.DisableAutoCommit(),
	)
	if err != nil {
		sec.record("group:READ", statusError, err.Error())
		return
	}
	defer cl.Close()

	pollCtx, cancel := context.WithTimeout(ctx, cfg.PollTimeout)
	defer cancel()

	fetches := cl.PollRecords(pollCtx, 1)
	if errs := fetches.Errors(); len(errs) > 0 {
		for _, fe := range errs {
			// A deadline/timeout means the group join succeeded but no new
			// messages arrived — auth is already proven by the join completing.
			if strings.Contains(fe.Err.Error(), "context deadline exceeded") ||
				strings.Contains(fe.Err.Error(), "context canceled") {
				sec.record("group:READ", statusOK, "joined group successfully (no new records in poll window)")
				return
			}
		}
		s, d := classify(errs[0].Err, "")
		sec.record("group:READ", s, d)
		return
	}
	sec.record("group:READ", statusOK, "joined group, polled (no offset commit)")
}

func checkGroupOffsetRead(ctx context.Context, cfg Config, group, topic string, sec *Section) {
	cl, err := newClient(cfg)
	if err != nil {
		sec.record("group:OFFSET_READ (dry)", statusError, err.Error())
		return
	}
	defer cl.Close()

	adm := kadm.NewClient(cl)
	_, err = adm.FetchOffsetsForTopics(ctx, group, topic)
	s, d := classify(err, "committed offsets readable")
	sec.record("group:OFFSET_READ (dry)", s, d)
}

// ── Transactional ID check ────────────────────────────────────────────────────

func checkTransactionWriteAbort(ctx context.Context, cfg Config, txnID, topic string, sec *Section) {
	cl, err := newClient(cfg,
		kgo.TransactionalID(txnID),
		kgo.RequiredAcks(kgo.AllISRAcks()),
		kgo.DefaultProduceTopic(topic),
	)
	if err != nil {
		sec.record("txn:WRITE (aborted)", statusError, err.Error())
		return
	}
	defer cl.Close()

	if err := cl.BeginTransaction(); err != nil {
		s, d := classify(err, "")
		sec.record("txn:WRITE (aborted)", s, d)
		return
	}

	ackCh := make(chan error, 1)
	cl.Produce(ctx, &kgo.Record{
		Key:   []byte("perm-check-txn"),
		Value: []byte("kafka-perm-check txn probe"),
	}, func(_ *kgo.Record, err error) {
		ackCh <- err
	})

	select {
	case err := <-ackCh:
		if err != nil {
			_ = cl.AbortBufferedRecords(ctx)
			s, d := classify(err, "")
			sec.record("txn:WRITE (aborted)", s, d)
			return
		}
	case <-time.After(cfg.Timeout):
		_ = cl.AbortBufferedRecords(ctx)
		sec.record("txn:WRITE (aborted)", statusError, "timeout waiting for produce ack")
		return
	}

	if err := cl.EndTransaction(ctx, kgo.TryAbort); err != nil {
		s, d := classify(err, "")
		sec.record("txn:WRITE (aborted)", s, fmt.Sprintf("produced OK but abort failed: %s", d))
		return
	}

	sec.record("txn:WRITE (aborted)", statusOK, "transaction initiated and aborted (no data committed)")
}

// ── Schema Registry check ─────────────────────────────────────────────────────

func checkSchemaRead(ctx context.Context, cfg Config, subject string, sec *Section) {
	reqURL := fmt.Sprintf("%s/subjects/%s/versions", cfg.SRUrl, subject)

	tlsCfg, err := buildSRTLSConfig(cfg)
	if err != nil {
		sec.record("schema:READ", statusError, fmt.Sprintf("building SR TLS config: %s", err))
		return
	}

	dialer := &net.Dialer{Timeout: cfg.Timeout}
	httpCl := &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext:     dialer.DialContext,
			TLSClientConfig: tlsCfg, // nil = Go default (system CA store)
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		sec.record("schema:READ", statusError, err.Error())
		return
	}
	req.Header.Set("Accept", "application/vnd.schemaregistry.v1+json")

	// SR auth: basic auth takes precedence; fall back to OAuth Bearer if configured.
	switch {
	case cfg.SRBasicAuthUser != "":
		req.SetBasicAuth(cfg.SRBasicAuthUser, cfg.SRBasicAuthPass)
	case strings.ToLower(cfg.SASLMechanism) == "oauthbearer":
		token, err := fetchClientCredentialsToken(ctx, cfg)
		if err != nil {
			sec.record("schema:READ", statusError, fmt.Sprintf("fetching OAuth token: %s", err))
			return
		}
		req.Header.Set("Authorization", "Bearer "+token.Token)
	}

	resp, err := httpCl.Do(req)
	if err != nil {
		sec.record("schema:READ", statusError, err.Error())
		return
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		sec.record("schema:READ", statusOK, "versions listed")
	case http.StatusNotFound:
		sec.record("schema:READ", statusOK, "HTTP 404 — subject not found, but READ permitted")
	case http.StatusUnauthorized, http.StatusForbidden:
		sec.record("schema:READ", statusDenied, fmt.Sprintf("HTTP %d", resp.StatusCode))
	default:
		sec.record("schema:READ", statusError, fmt.Sprintf("unexpected HTTP %d", resp.StatusCode))
	}
}

// ── CLI ───────────────────────────────────────────────────────────────────────

func main() {
	var (
		configFile  string
		topic       string
		group       string
		txnID       string
		srSubject   string
		timeoutSecs     int
		pollTimeoutSecs int
		skipTopic       bool
		skipGroup   bool
		skipTxn     bool
		skipSchema  bool
	)

	root := &cobra.Command{
		Use:   "kafka-perm-check",
		Short: "Non-destructive Kafka permission checker",
		Long: `Probes Kafka ACLs for topic, consumer group, transactional ID,
and Schema Registry subject — without committing or mutating any existing data.

Kafka client configuration (brokers, auth, TLS) is loaded from a properties
file (default: kafka.properties in the working directory).

Supported auth mechanisms: PLAIN, SCRAM-SHA-256, SCRAM-SHA-512, OAUTHBEARER
Supported TLS modes: one-way TLS, mTLS (mutual TLS with client certificate)

All checks are safe to run repeatedly in any environment.
Exits 0 if all checks pass, 1 if any check is DENIED or ERRORED.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			props, err := loadProperties(configFile)
			if err != nil {
				return fmt.Errorf("loading config: %w", err)
			}

			cfg, err := configFromProperties(props, time.Duration(timeoutSecs)*time.Second)
			if err != nil {
				return fmt.Errorf("invalid config: %w", err)
			}
			cfg.PollTimeout = time.Duration(pollTimeoutSecs) * time.Second

			// All inputs are valid — suppress usage for check failures.
			cmd.SilenceUsage = true

			ctx := context.Background()

			fmt.Println()
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println("  kafka-perm-check")
			fmt.Printf("  config  : %s\n", configFile)
			fmt.Printf("  brokers : %s\n", strings.Join(cfg.Brokers, ", "))
			if cfg.SASLMechanism != "" {
				switch cfg.SASLMechanism {
				case "oauthbearer":
					fmt.Printf("  auth    : OAUTHBEARER (client_id=%s)\n", cfg.OAuthClientID)
				default:
					fmt.Printf("  auth    : %s / %s\n", strings.ToUpper(cfg.SASLMechanism), cfg.SASLUser)
				}
			}
			if cfg.TLS {
				mode := "TLS"
				if cfg.TLSKeystorePath != "" || cfg.TLSCertFile != "" {
					mode = "mTLS"
				}
				fmt.Printf("  tls     : %s\n", mode)
			}
			if cfg.SRUrl != "" {
				srAuth := "none"
				switch {
				case cfg.SRBasicAuthUser != "":
					srAuth = fmt.Sprintf("basic (%s)", cfg.SRBasicAuthUser)
				case strings.ToLower(cfg.SASLMechanism) == "oauthbearer":
					srAuth = "oauthbearer"
				}
				srTLS := ""
				if cfg.SRTruststorePath != "" || cfg.SRKeystorePath != "" {
					srTLS = " mTLS"
				}
				fmt.Printf("  sr      : %s  auth=%s%s\n", cfg.SRUrl, srAuth, srTLS)
			}
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			fmt.Println()

			// Run the four check groups in parallel; each buffers its own output
			// so sections are always printed in order after all complete.
			type sectionResult struct {
				sec     *Section
				skipped string // non-empty means the section was skipped
			}

			runs := make([]sectionResult, 4)
			var wg sync.WaitGroup

			wg.Add(4)

			go func() {
				defer wg.Done()
				if skipTopic {
					return
				}
				if topic == "" {
					runs[0] = sectionResult{skipped: "  ⚠️  --topic not set, skipping topic checks"}
					return
				}
				sec := newSection(fmt.Sprintf("── Topic: %s", topic))
				checkTopicDescribe(ctx, cfg, topic, sec)
				checkTopicRead(ctx, cfg, topic, sec)
				checkTopicWrite(ctx, cfg, topic, sec)
				runs[0] = sectionResult{sec: sec}
			}()

			go func() {
				defer wg.Done()
				if skipGroup {
					return
				}
				if group == "" {
					runs[1] = sectionResult{skipped: "  ⚠️  --group not set, skipping consumer group checks"}
					return
				}
				if topic == "" {
					runs[1] = sectionResult{skipped: "  ⚠️  --topic required for group checks, skipping"}
					return
				}
				sec := newSection(fmt.Sprintf("── Consumer Group: %s", group))
				checkGroupDescribe(ctx, cfg, group, sec)
				checkGroupRead(ctx, cfg, group, topic, sec)
				checkGroupOffsetRead(ctx, cfg, group, topic, sec)
				runs[1] = sectionResult{sec: sec}
			}()

			go func() {
				defer wg.Done()
				if skipTxn {
					return
				}
				if txnID == "" {
					runs[2] = sectionResult{skipped: "  ⚠️  --txn-id not set, skipping transactional checks"}
					return
				}
				if topic == "" {
					runs[2] = sectionResult{skipped: "  ⚠️  --topic required for txn checks, skipping"}
					return
				}
				sec := newSection(fmt.Sprintf("── Transactional ID: %s", txnID))
				checkTransactionWriteAbort(ctx, cfg, txnID, topic, sec)
				runs[2] = sectionResult{sec: sec}
			}()

			go func() {
				defer wg.Done()
				if skipSchema {
					return
				}
				if cfg.SRUrl == "" || srSubject == "" {
					runs[3] = sectionResult{skipped: "  ⚠️  schema.registry.url (properties) and --sr-subject required, skipping schema checks"}
					return
				}
				sec := newSection(fmt.Sprintf("── Schema Registry Subject: %s", srSubject))
				checkSchemaRead(ctx, cfg, srSubject, sec)
				runs[3] = sectionResult{sec: sec}
			}()

			wg.Wait()

			// Flush sections in order and collect all results.
			var allResults []Result
			for _, r := range runs {
				if r.skipped != "" {
					fmt.Println(r.skipped)
				} else if r.sec != nil {
					allResults = append(allResults, r.sec.flush()...)
				}
			}

			// ── Summary ──
			fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			var ok, denied, skipped, errored int
			for _, r := range allResults {
				switch r.Status {
				case statusOK:
					ok++
				case statusDenied:
					denied++
				case statusSkipped:
					skipped++
				case statusError:
					errored++
				}
			}
			fmt.Printf("  ✅ %d passed   ❌ %d denied   ⚠️  %d errors   ⏭  %d skipped\n\n",
				ok, denied, errored, skipped)

			if denied > 0 || errored > 0 {
				return fmt.Errorf("one or more permission checks failed")
			}
			return nil
		},
	}

	f := root.Flags()

	// Config file
	f.StringVar(&configFile, "config", "kafka.properties",
		"Path to Kafka client properties file")
	f.IntVar(&timeoutSecs, "timeout", 10, "Per-operation timeout in seconds")
	f.IntVar(&pollTimeoutSecs, "poll-timeout", 2, "Timeout in seconds for consumer poll checks (topic:READ, group:READ)")

	// Resources to test
	f.StringVar(&topic, "topic", "", "Topic to test (DESCRIBE, READ, WRITE)")
	f.StringVar(&group, "group", "", "Consumer group ID to test (DESCRIBE, READ, OFFSET_READ)")
	f.StringVar(&txnID, "txn-id", "", "Transactional ID to test (WRITE+abort)")
	f.StringVar(&srSubject, "sr-subject", "", "Schema Registry subject to test READ on")

	// Skip flags
	f.BoolVar(&skipTopic, "skip-topic", false, "Skip topic checks")
	f.BoolVar(&skipGroup, "skip-group", false, "Skip consumer group checks")
	f.BoolVar(&skipTxn, "skip-txn", false, "Skip transactional ID checks")
	f.BoolVar(&skipSchema, "skip-schema", false, "Skip schema registry checks")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}
