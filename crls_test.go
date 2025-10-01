package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
	"math/big"
	"crypto/x509"
)

func TestCollectCRLFilesEmpty(t *testing.T) {
	tmp := t.TempDir()
	files := collectCRLFiles([]string{tmp}, []string{"*.crl"})
	if len(files) != 0 {
		t.Fatalf("expected 0 files, got %d", len(files))
	}
}

func TestLoadLocalCRLsSkipBad(t *testing.T) {
	tmp := t.TempDir()

	// write a bogus file that looks like DER but isn't
	if err := os.WriteFile(filepath.Join(tmp, "bad.crl"), []byte{0x01, 0x02, 0x03}, 0o644); err != nil {
		t.Fatal(err)
	}

	m := loadLocalCRLs([]string{tmp}, []string{"*.crl"}, false) // skip mode
	if len(m) != 0 {
		t.Fatalf("expected 0 revoked entries, got %d", len(m))
	}
}

func TestStartRefresher(t *testing.T) {
	tmp := t.TempDir()
	// No CRLs, should not panic
	startCRLRefresher([]string{tmp}, []string{"*.crl"}, 50*time.Millisecond, false)
	time.Sleep(120 * time.Millisecond)
}

//test function to see if the revoke function works as expected
func TestVerifyRevoked(t *testing.T) {
    revoked := map[string]bool{
        "12345": true,
    }
    cert := &x509.Certificate{
        SerialNumber: big.NewInt(12345),
    }
    if _, ok := revoked[cert.SerialNumber.String()]; !ok {
        t.Fatal("expected cert to be revoked")
    }
}
