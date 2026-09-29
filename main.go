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

	"certfinder/internal/argparser"
	"certfinder/internal/certificates"
	"certfinder/internal/display"
	"certfinder/internal/models"
	"certfinder/internal/report"
	"certfinder/internal/storage"
	"certfinder/internal/subfinder"
)



func main() {
	m := Main{}
	m.execute()
}



type Main struct {
	args  *argparser.Arguments
	data   map[string]struct{}
}



func (m *Main) execute() {
	m.getArgs()
	m.getDomainsFromSubfinder()
	m.getCertInfo()
	m.writeExcel()
}



func (m *Main) getArgs() {
	ap     := argparser.NewParser()
	m.args  = ap.GetArgs()
}



func (m *Main) getDomainsFromSubfinder() {
	s := subfinder.NewSubfinder(m.args)
	
	domains, err := s.Run()

	if err != nil {
	    display.Fatal(err)
	}

	if len(domains) == 0 {
		display.Fatal(fmt.Errorf("no subdomain found"))
	}

	fmt.Printf("[*] %d subdomains found\n", len(domains))

	m.data = domains
}



func (m *Main) getCertInfo() {
	info, err := certificates.GetCertInfo(m.data)

	if err != nil {
	    display.Fatal(err)
	}
	
	updateDatabase(info)
}



func updateDatabase(info []models.Domain) {
	if err := storage.UpsertDomains(info); err != nil {
	    display.Fatal(err)
	}

	storage.DisplayStats()
	storage.DisplayAlerts()
	storage.DisplayStale(7, 20)
}



func (m *Main) writeExcel() {
	if m.args.ExcelFilePath == "" {
		return
	}

	if err := report.ExportXLSX(m.args.ExcelFilePath); err != nil {
	    display.Fatal(err)
	}

	fmt.Printf("[i] Excel created in %s\n", m.args.ExcelFilePath)
}