// Copyright 2026 Oliver R. Calazans Jeronimo
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package certificates inspects TLS certificates served by subdomains,
// extracting issuer, validity dates, and remaining days until expiration.
package certificates

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
	"time"

	"certfinder/internal/models"
)

// GetCertInfo inspects the TLS certificate served by every host in domains,
// running up to MaxWorkers checks in parallel. Hosts that fail TLS are
// retried against HTTP on port 80 to catch servers that only respond over
// plain HTTP or that redirect to a different HTTPS endpoint.
//
// The returned slice preserves no particular order and contains one entry
// per input host, including hosts that failed — their Domain.Error field
// describes the failure.
func GetCertInfo(domains map[string]struct{}) ([]models.Domain, error) {
	total   := len(domains)
	workers := max(1, min(MaxWorkers, total))
	jobs    := make(chan string, total)
	results := make(chan models.Domain, total)

	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for h := range jobs {
				results <- getCertificate(h)
			}
		})
	}

	go func() {
		for h := range domains {
			jobs <- h
		}
		close(jobs)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	out  := make([]models.Domain, 0, total)
	done := 0

	for r := range results {
		out = append(out, r)
		done++
		fmt.Printf("  [%d/%d]\r", done, total)
	}

	fmt.Print("                    \r")
	return out, nil
}



func getCertificate(domain string) models.Domain {
	dom := models.Domain{Name: domain}

	der, errMsg, wasVerifyErr := tryFetch(domain, Port)

	// If fetch failed for a reason other than verification, try HTTP.
	if der == nil && !wasVerifyErr {
		hc := checkHTTP(domain)

		switch hc.Kind {
		case redirect:
			if hc.Host != domain || hc.Port != Port {
				der2, errMsg2, _ := tryFetch(hc.Host, hc.Port)
				
				if der2 == nil {
					dom.Error = fmt.Sprintf(
						"%s | redirect to %s:%d failed: %s",
						errMsg, hc.Host, hc.Port, errMsg2,
					)
				
					return dom
				}

				der = der2
			}
		case httpOnly:
			dom.Error = fmt.Sprintf(
				"%s | responds only on port 80 (HTTP, no redirect to HTTPS)", errMsg,
			)
			return dom
		}
	}

	if der == nil {
		dom.Error = errMsg
		return dom
	}

	if err := parseCert(der, domain, &dom); err != nil {
		dom.Error = fmt.Sprintf("unable to parse cert: %v", err)
	}

	return dom
}



// tryFetch attempts to retrieve the leaf certificate from host:port,
// falling back through three TLS configurations:
//
//  1. Full validation (system CAs, hostname check)
//  2. No validation (accepts expired, self-signed, hostname mismatch)
//  3. No validation + legacy ciphers (SECLEVEL=1 equivalent)
//
// The boolean return reports whether the failure was certificate
// verification (as opposed to connection or protocol errors), so callers
// can decide whether an HTTP fallback is worthwhile.
func tryFetch(host string, port int) ([]byte, string, bool) {
	der1, err1 := fetchCertDER(host, port, true, false)
	if err1 == nil {
		return der1, "", false
	}

	if isCertVerifyError(err1) {
		// Cert was presented but failed validation - grab it without verifying.
		der2, err2 := fetchCertDER(host, port, false, false)
		if err2 == nil {
			return der2, "", true
		}

		der3, err3 := fetchCertDER(host, port, false, true)
		if err3 == nil {
			return der3, "", true
		}
		
		return nil, fmt.Sprintf(
			"verification failed (%v); unverified failed (%v); permissive failed (%v)",
			err1, err2, err3,
		), true
	}

	// TLS protocol/cipher error — try permissive mode.
	der2, err2 := fetchCertDER(host, port, false, true)
	if err2 == nil {
		return der2, "", false
	}

	if isTimeoutError(err1) {
		return nil, fmt.Sprintf("connection / DNS: %v", err1), false
	}

	if isRefusedError(err1) {
		return nil, "connection refused", false
	}
	
	return nil, fmt.Sprintf("unable to fetch cert: %v", err1), false
}



func parseCert(der []byte, domain string, dom *models.Domain) error {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}

	cn := cert.Subject.CommonName
	if cn == "" {
		cn = domain
	}
	dom.CommonName = cn

	switch {
	case len(cert.Issuer.Organization) > 0:
		dom.Issuer = cert.Issuer.Organization[0]
	case cert.Issuer.CommonName != "":
		dom.Issuer = cert.Issuer.CommonName
	default:
		dom.Issuer = "Unknown"
	}

	nb := cert.NotBefore.UTC()
	na := cert.NotAfter.UTC()
	
	dom.NotBefore = &nb
	dom.NotAfter  = &na

	now := time.Now().UTC()
	
	dom.RemainingDays = int(na.Sub(now).Hours() / 24)
	dom.Expired       = dom.RemainingDays < 0
	dom.Alert 		  = dom.RemainingDays >= 0 && dom.RemainingDays <= 30

	if strings.HasPrefix(cn, "*") {
		dom.CertType = "Wildcard (*)"
	} else {
		dom.CertType = "Standard"
	}

	return nil
}