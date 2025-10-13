// crls.go
package main

import (
	"fmt"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
 	"net/http"
)

// revoked cert serials (swap with atomic.Value)
var revoked atomic.Value

// collectCRLFiles builds the file list once (O(n)) across dirs and patterns.
func collectCRLFiles(dirs, globs []string) []string {
	var files []string
	patts := globs
	if len(patts) == 0 {
		// default patterns if none provided
		patts = []string{"*.[rR][0-9]", "*.crl"}
	}
	for _, dir := range dirs {
		for _, pat := range patts {
			m, _ := filepath.Glob(filepath.Join(dir, pat))
			if len(m) > 0 {
				files = append(files, m...)
			}
		}
	}
	return files
}

// quarantineFile renames a bad CRL to .bad; if rename fails, remove it.
func quarantineFile(path string) {
	bad := path + ".bad"
	if err := os.Rename(path, bad); err != nil {
		log.Printf("failed to quarantine %s: %v; removing", path, err)
		if rmErr := os.Remove(path); rmErr != nil {
			log.Printf("failed to remove %s: %v", path, rmErr)
		}
	} else {
		log.Printf("quarantined bad CRL %s -> %s", path, bad)
	}
}

// parseCRLBytes decodes DER/PEM, validates freshness, and accumulates serials.
func parseCRLBytes(data []byte, path string, out map[string]bool, now time.Time) error {
	// accept PEM-wrapped or raw DER
	if strings.Contains(string(data), "-----BEGIN") {
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			data = rest
			if !strings.Contains(block.Type, "CRL") {
				continue
			}
			crl, err := x509.ParseCRL(block.Bytes)
			if err != nil {
				return err
			}
			if crl.HasExpired(now) {
				log.Printf("WARNING expired CRL %s (ignored)", path)
				continue
			}
			for _, rc := range crl.TBSCertList.RevokedCertificates {
				out[rc.SerialNumber.String()] = true
			}
		}
		return nil
	}

	// raw DER
	crl, err := x509.ParseCRL(data)
	if err != nil {
		return err
	}
	if crl.HasExpired(now) {
		log.Printf("WARNING expired CRL %s (ignored)", path)
		return nil
	}
	for _, rc := range crl.TBSCertList.RevokedCertificates {
		out[rc.SerialNumber.String()] = true
	}
	return nil
}

// loadLocalCRLs builds revoked set from dirs+globs; skips or quarantines bad files per config.
func loadLocalCRLs(dirs, globs []string, quarantine bool) map[string]bool {
	out := make(map[string]bool)
	now := time.Now()

	files := collectCRLFiles(dirs, globs)
	if len(files) == 0 && Config.Verbose > 0 {
		log.Printf("No CRL files found in %v with patterns %v", dirs, globs)
	}

	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("Failed to read CRL %s: %v", f, err)
			continue
		}
		if err := parseCRLBytes(data, f, out, now); err != nil {
			log.Printf("Failed to parse CRL %s: %v", f, err)
			if quarantine {
				quarantineFile(f)
			}
			continue
		}
		if Config.Verbose > 0 {
			log.Printf("Loaded CRL %s", f)
		}
	}
	log.Printf("[CRL-DEBUG] TOTAL revoked certs loaded: %d", len(out))
	return out
}

// startCRLRefresher periodically reloads CRLs and swaps the map atomically.
func startCRLRefresher(dirs, globs []string, interval time.Duration, quarantine bool) {
	go func() {
		for {
			m := loadLocalCRLs(dirs, globs, quarantine)
			revoked.Store(m)
			if Config.Verbose > 0 {
				log.Printf("CRLs refreshed, %d revoked certs loaded", len(m))
			}
			time.Sleep(interval)
		}
	}()
}

// RefreshCRLsHandler handles PUT /refresh-crls to reload CRLs manually.
// It updates the revoked certificates map used for TLS verification.
func RefreshCRLsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		w.Header().Set("Allow", http.MethodPut)
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := refreshCRLsNow(Config.CRLDirs, Config.CRLGlobs, Config.CRLQuarantine); err != nil {
		log.Printf("[CRL] manual refresh failed: %v", err)
		http.Error(w, fmt.Sprintf("Failed to refresh CRLs: %v\n", err), http.StatusInternalServerError)
		return
	}

	log.Printf("[CRL] manual refresh successful")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("CRLs refreshed successfully\n"))
}

// refreshCRLsNow forces an immediate reload.
func refreshCRLsNow(dirs, globs []string, quarantine bool) error {
	m := loadLocalCRLs(dirs, globs, quarantine)
    if len(m) == 0 {
        return fmt.Errorf("no CRLs loaded from %v", dirs)
    }
	revoked.Store(m)
    log.Printf("[CRL] Refreshed %d revoked certs", len(m))
    return nil
}

// verifyPeerCertificate enforces CRL-based revocation for the leaf cert.
func verifyPeerCertificateWithCRL(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("no verified chains")
	}
	leaf := verifiedChains[0][0]
	crls, _ := revoked.Load().(map[string]bool)
	if crls == nil {
		return nil // no CRLs loaded yet -> do not block
	}
	if _, ok := crls[leaf.SerialNumber.String()]; ok {
		return fmt.Errorf("certificate revoked: %s", leaf.SerialNumber)
	}
	return nil
}

