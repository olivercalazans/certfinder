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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
)


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

// HTTP check (port 80)
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

	for range MaxRedirects {
		u := fmt.Sprintf("http://%s%s", currentHost, currentPath)

		req, err := http.NewRequest("HEAD", u, nil)
		if err != nil { return httpCheckResult{Kind: "no_response"} }

		resp, err := client.Do(req)
		if err != nil { return httpCheckResult{Kind: "no_response"} }
		resp.Body.Close()

		location := resp.Header.Get("Location")
		if location == "" { return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort} }

		parsed, err := url.Parse(location)
		if err != nil { return httpCheckResult{Kind: "http_only", Host: currentHost, Port: HTTPPort} }

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