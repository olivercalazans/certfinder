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

package certificates

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"certfinder/internal/models"
)

const (
	Port         = 443
	HTTPPort     = 80
	Timeout      = 5 * time.Second
	MaxRedirects = 5
	MaxWorkers   = 20
)

var permissiveCiphers = []uint16{
	tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
}

// ─────────────────────────────────────────────────────────────
// TLS fetch
// ─────────────────────────────────────────────────────────────
func fetchCertDER(host string, port int, verify, permissive bool) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	dialer := &net.Dialer{Timeout: Timeout}
	addr := net.JoinHostPort(host, strconv.Itoa(port))

	rawConn, err := dialer.DialContext(ctx, "tcp4", addr)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: !verify,
	}
	if permissive {
		cfg.MinVersion = tls.VersionTLS10
		cfg.CipherSuites = permissiveCiphers
	}

	tlsConn := tls.Client(rawConn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("no peer certificates")
	}
	return state.PeerCertificates[0].Raw, nil
}

// ─────────────────────────────────────────────────────────────
// HTTP check (port 80)
// ─────────────────────────────────────────────────────────────
type httpCheckResult struct {
	Kind string // "redirect", "http_only", "no_response"
	Host string
	Port int
}

func checkHTTP(host string) httpCheckResult {
	client := &http.Client{
		Timeout: Timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: Timeout,
			}).DialContext,
		},
	}

	currentHost := host
	currentPath := "/"

	for i := 0; i < MaxRedirects; i++ {
		u := fmt.Sprintf("http://%s%s", currentHost, currentPath)
		req, err := http.NewRequest("HEAD", u, nil)
		if err != nil {
			return httpCheckResult{Kind: "no_response"}
		}

		resp, err := client.Do(req)
		if err != nil {
			return httpCheckResult{Kind: "no_response"}
		}
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if location == "" {
			return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort}
		}

		parsed, err := url.Parse(location)
		if err != nil {
			return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort}
		}

		if parsed.Scheme == "https" {
			nextHost := parsed.Hostname()
			if nextHost == "" {
				nextHost = currentHost
			}
			nextPort := Port
			if parsed.Port() != "" {
				if p, err := strconv.Atoi(parsed.Port()); err == nil {
					nextPort = p
				}
			}
			return httpCheckResult{Kind: "redirect", Host: nextHost, Port: nextPort}
		}

		if parsed.Scheme == "" || parsed.Scheme == "http" {
			if parsed.Hostname() != "" {
				currentHost = parsed.Hostname()
			}
			if parsed.Path != "" {
				currentPath = parsed.Path
			}
			continue
		}

		return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort}
	}

	return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort}
}

// ─────────────────────────────────────────────────────────────
// Parsing
// ─────────────────────────────────────────────────────────────
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
	dom.NotAfter = &na

	now := time.Now().UTC()
	dom.RemainingDays = int(na.Sub(now).Hours() / 24)
	dom.Expired = dom.RemainingDays < 0
	dom.Alert = dom.RemainingDays >= 0 && dom.RemainingDays <= 30

	if strings.HasPrefix(cn, "*") {
		dom.CertType = "Wildcard (*)"
	} else {
		dom.CertType = "Standard"
	}

	return nil
}

// ─────────────────────────────────────────────────────────────
// Error classification
// ─────────────────────────────────────────────────────────────
func isCertVerifyError(err error) bool {
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return true
	}
	var unknownAuth x509.UnknownAuthorityError
	if errors.As(err, &unknownAuth) {
		return true
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return true
	}
	var invalidErr x509.CertificateInvalidError
	if errors.As(err, &invalidErr) {
		return true
	}
	return false
}

func isTimeoutError(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func isRefusedError(err error) bool {
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return strings.Contains(strings.ToLower(opErr.Error()), "connection refused")
	}
	return false
}

// ─────────────────────────────────────────────────────────────
// Cascade: verify → unverified → permissive
// ─────────────────────────────────────────────────────────────
// Returns (der, errMsg, wasVerificationError)
func tryFetch(host string, port int) ([]byte, string, bool) {
	der1, err1 := fetchCertDER(host, port, true, false)
	if err1 == nil {
		return der1, "", false
	}

	if isCertVerifyError(err1) {
		// Cert was presented but failed validation — grab it without verifying.
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

// ─────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────
func GetCertInfo(domain string) models.Domain {
	dom := models.Domain{Name: domain}

	der, errMsg, wasVerifyErr := tryFetch(domain, Port)

	// If fetch failed for a reason other than verification, try HTTP.
	if der == nil && !wasVerifyErr {
		hc := checkHTTP(domain)

		switch hc.Kind {
		case "redirect":
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
		case "http_only":
			dom.Error = fmt.Sprintf(
				"%s | responds only on port 80 (HTTP, no redirect to HTTPS)",
				errMsg,
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

func GetDomainListCertInfo(domains map[string]struct{}) []models.Domain {
	total := len(domains)
	workers := MaxWorkers
	if total < workers {
		workers = total
	}
	if workers < 1 {
		workers = 1
	}

	jobs := make(chan string, total)
	results := make(chan models.Domain, total)

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for h := range jobs {
				results <- GetCertInfo(h)
			}
		}()
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

	out := make([]models.Domain, 0, total)
	done := 0

	for r := range results {
		out = append(out, r)
		done++
		fmt.Printf("  [%d/%d]\r", done, total)
	}

	fmt.Print("                    \r")
	return out
}
