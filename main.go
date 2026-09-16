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

package main

import (
	"fmt"
	"os"

	"certfinder/internal/certificates"
	"certfinder/internal/report"
	"certfinder/internal/storage"
	"certfinder/internal/subfinder"
)



func main() {
	m := Main{}
	m.getDomainsFromSubfinder()
	m.getCertInfo()
}



type Main struct {
	data map[string]struct{}
}



func fatal(msg string) {
	fmt.Fprintf(os.Stderr, "[ ERR ] %s\n", msg)
	os.Exit(1)
}



func (m *Main) getDomainsFromSubfinder() {
	s := subfinder.Subfinder{}

	domains, err := s.Run(BaseDomain, DomainsToRemove)

	if err != nil {
	    fatal(err.Error())
	}

	if len(domains) == 0 {
		fatal("No subdomain found")
	}

	fmt.Printf("[+] %d subdomains found\n", len(domains))

	m.data = domains
}



func (m *Main) getCertInfo() {
	info := certificates.GetDomainListCertInfo(m.data)

	if err := storage.UpsertDomains(info); err != nil {
		fatal(err.Error())
	}

	storage.DisplayStats()
	storage.DisplayAlerts()
	storage.DisplayStale(7, 20)

	if err := report.ExportXLSX("certificates.xlsx"); err != nil {
		fatal(err.Error())
	}
}