package main

import (
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

// loadLocalCRLs parses CRLs from multiple dirs and returns a map of revoked cert serials.
func loadLocalCRLs(dirs []string) map[string]bool {
	revoked := make(map[string]bool)

	for _, certsDir := range dirs {
		// Collect *.crl and *.[rR][0-9] files
		files, _ := filepath.Glob(filepath.Join(certsDir, "*.[rR][0-9]"))
		more, _ := filepath.Glob(filepath.Join(certsDir, "*.crl"))
		files = append(files, more...)

		if len(files) == 0 {
			log.Printf("No CRL files found in %s", certsDir)
			continue
		}

		for _, f := range files {
			data, err := os.ReadFile(f)
			if err != nil {
				log.Printf("Failed to read CRL file %s: %v", f, err)
				continue
			}

			// Handle PEM-wrapped CRLs
			if block, _ := pem.Decode(data); block != nil && strings.Contains(block.Type, "CRL") {
				data = block.Bytes
			}

			crl, err := x509.ParseCRL(data)
			if err != nil {
				log.Printf("Failed to parse CRL file %s: %v", f, err)
				continue
			}

			for _, rc := range crl.TBSCertList.RevokedCertificates {
				revoked[rc.SerialNumber.String()] = true
			}
		}
	}

	return revoked
}

// startCRLRefresher periodically reloads CRLs from all given dirs.
func startCRLRefresher(dirs []string, interval time.Duration) {
	go func() {
		for {
			crls := loadLocalCRLs(dirs)
			revoked.Store(crls)
			log.Printf("CRLs refreshed, %d revoked certs loaded", len(crls))
			time.Sleep(interval)
		}
	}()
}

// refreshCRLsNow allows immediately reloading CRLs (used by /refresh-crls endpoint).
func refreshCRLsNow(dirs []string) {
	crls := loadLocalCRLs(dirs)
	revoked.Store(crls)
	log.Printf("CRLs force-refreshed, %d revoked certs loaded", len(crls))
}

