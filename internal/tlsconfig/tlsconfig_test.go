package tlsconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCert(t *testing.T, dir string) (string, string, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	return certPath, keyPath, certPEM
}

func TestConfigureWithCertAndKey(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeSelfSignedCert(t, dir)

	cfg, err := Configure("", certPath, keyPath, false)
	if err != nil {
		t.Fatalf("Configure error: %v", err)
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected TLS min version 1.2, got %v", cfg.MinVersion)
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("expected one certificate, got %d", len(cfg.Certificates))
	}
	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("expected no client auth, got %v", cfg.ClientAuth)
	}
}

func TestConfigureWithMTLS(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, caPEM := writeSelfSignedCert(t, dir)
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write ca: %v", err)
	}

	cfg, err := Configure(caPath, certPath, keyPath, true)
	if err != nil {
		t.Fatalf("Configure error: %v", err)
	}
	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("expected client cert auth, got %v", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatalf("expected ClientCAs to be set")
	}
	if cfg.RootCAs == nil {
		t.Fatalf("expected RootCAs to be set")
	}
}

func TestConfigureInvalidCA(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath, _ := writeSelfSignedCert(t, dir)
	caPath := filepath.Join(dir, "bad-ca.pem")
	if err := os.WriteFile(caPath, []byte("not a pem"), 0o600); err != nil {
		t.Fatalf("write invalid ca: %v", err)
	}

	if _, err := Configure(caPath, certPath, keyPath, false); err == nil {
		t.Fatalf("expected error for invalid CA bundle")
	}
}

func TestConfigureMissingCert(t *testing.T) {
	dir := t.TempDir()
	if _, err := Configure("", filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"), false); err == nil {
		t.Fatalf("expected error for missing cert/key")
	}
}
