package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// helper to make a dummy certificate
func makeDummyCert(t *testing.T) *x509.Certificate {
	serial, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		t.Fatal(err)
	}
	return &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
}

// tests empty CRL directory
func TestCollectCRLFilesEmpty(t *testing.T) {
	tmpDir := t.TempDir()
	files := collectCRLFiles([]string{tmpDir}, []string{"*.crl"})
	if len(files) != 0 {
		t.Errorf("expected 0 files, got %d", len(files))
	}
}

// tests loading invalid CRL file
func TestLoadLocalCRLsSkipBad(t *testing.T) {
	tmpDir := t.TempDir()
	badFile := filepath.Join(tmpDir, "bad.crl")
	if err := os.WriteFile(badFile, []byte("not a crl"), 0644); err != nil {
		t.Fatal(err)
	}

	out := loadLocalCRLs([]string{tmpDir}, []string{"*.crl"}, false)
	if len(out) != 0 {
		t.Errorf("expected 0 revoked certs, got %d", len(out))
	}
}

// tests that the CRL refresher goroutine starts and runs
func TestStartRefresher(t *testing.T) {
	tmpDir := t.TempDir()
	done := make(chan struct{})
	go func() {
		startCRLRefresher([]string{tmpDir}, []string{"*.crl"}, 100*time.Millisecond, false)
		time.Sleep(300 * time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for refresher")
	}
}

// tests VerifyPeerCertificateWithCRL behavior
func TestVerifyPeerCertificateWithCRL(t *testing.T) {
	cert := makeDummyCert(t)
	chain := [][]*x509.Certificate{{cert}}

	mockRevoked := map[string]bool{}
	revoked.Store(mockRevoked)

	// not revoked
	err := verifyPeerCertificateWithCRL(nil, chain)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}

	// revoked
	mockRevoked[cert.SerialNumber.String()] = true
	revoked.Store(mockRevoked)
	err = verifyPeerCertificateWithCRL(nil, chain)
	if err == nil {
		t.Errorf("expected revocation error, got nil")
	}
}

// tests atomic safety of revoked map
func TestRevokedMapAtomicity(t *testing.T) {
	m := map[string]bool{"1234": true}
	revoked.Store(m)

	val := revoked.Load().(map[string]bool)
	if _, ok := val["1234"]; !ok {
		t.Error("expected to find revoked serial 1234")
	}
}

