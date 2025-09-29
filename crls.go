// crls.go
package main

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// revoked cert serials (refreshed periodically)
var revoked atomic.Value

// quarantineFile renames a bad CRL to .bad; if that fails, it removes it.
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

// loadLocalCRLs parses CRLs from all provided dirs, handling corrupt/expired files.
func loadLocalCRLs(dirs []string) map[string]bool {
	out := make(map[string]bool)
	now := time.Now()

	for _, dir := range dirs {
		files1, _ := filepath.Glob(filepath.Join(dir, "*.[rR][0-9]"))
		files2, _ := filepath.Glob(filepath.Join(dir, "*.crl"))
		files := append(files1, files2...)

		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				log.Printf("ERROR reading CRL %s: %v", f, err)
				continue
			}

			// If PEM, handle potentially multiple PEM blocks
			if bytes.Contains(data, []byte("-----BEGIN")) {
				rest := data
				processedAny := false
				for {
					var block *pem.Block
					block, rest = pem.Decode(rest)
					if block == nil {
						break
					}
					if !strings.Contains(block.Type, "CRL") {
						continue
					}
					if err := addCRL(block.Bytes, f, out, now); err != nil {
						quarantineFile(f)
						processedAny = true // to avoid double quarantine attempt
						break
					}
					processedAny = true
				}
				// If it looked like PEM but we couldn't decode any CRL block, quarantine it.
				if !processedAny {
					log.Printf("ERROR: no CRL PEM blocks found in %s; quarantining", f)
					quarantineFile(f)
				}
				continue
			}

			// Otherwise treat as DER
			if err := addCRL(data, f, out, now); err != nil {
				quarantineFile(f)
				continue
			}
		}
	}
	return out
}

// addCRL parses a single DER-encoded CRL and adds its revoked serials to out.
func addCRL(der []byte, path string, out map[string]bool, now time.Time) error {
	crl, err := x509.ParseCRL(der)
	if err != nil {
		log.Printf("ERROR parsing CRL %s: %v", path, err)
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

// startCRLRefresher reloads CRLs from all dirs on the given interval.
func startCRLRefresher(dirs []string, interval time.Duration) {
	go func() {
		for {
			m := loadLocalCRLs(dirs)
			revoked.Store(m)
			log.Printf("CRLs refreshed, %d revoked certs loaded", len(m))
			time.Sleep(interval)
		}
	}()
}

// refreshCRLsNow forces an immediate reload of CRLs from all dirs.
func refreshCRLsNow(dirs []string) {
	m := loadLocalCRLs(dirs)
	revoked.Store(m)
	log.Printf("manual CRL refresh done, %d revoked certs loaded", len(m))
}

