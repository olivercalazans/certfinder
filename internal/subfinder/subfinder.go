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

package subfinder

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)



type Subfinder struct {
	baseDomain    string
	subsToRemove  string
	domains       map[string]struct{}
}



func (s *Subfinder) Run(baseDomain, removePattern string) (map[string]struct{}, error) {
	fmt.Printf("[+] Looking for %s subdomains\n", baseDomain)

	s.baseDomain   = baseDomain
	s.subsToRemove = removePattern

	if err := s.runSubfinder(); err != nil {
		return nil, err
	}

	if err := s.prune(); err != nil {
		return nil, err
	}

	return s.domains, nil
}



func (s *Subfinder) runSubfinder() error {
	options := &runner.Options{
		Threads            : 10,
		Timeout            : 30,
		MaxEnumerationTime : 10,
		Silent             : true,
		All                : true,
	}

	r, err := runner.NewRunner(options)
	
	if err != nil {
		return fmt.Errorf("failed to create runner: %w", err)
	}

	raw, err := r.EnumerateSingleDomainWithCtx(
		context.Background(),
		s.baseDomain,
		nil,
	)

	if err != nil {
		return fmt.Errorf("enumeration failed: %w", err)
	}
	
	s.domains = make(map[string]struct{}, len(raw))
	for host := range raw {
	    s.domains[host] = struct{}{}
	}

	return nil
}



func (s *Subfinder) prune() error {
	re, err := regexp.Compile(s.subsToRemove)

	if err != nil {
		return fmt.Errorf("invalid prune regex: %w", err)
	}

	for host := range s.domains {
		if !strings.HasSuffix(host, s.baseDomain) || re.MatchString(host) {
			delete(s.domains, host)
		}
	}

	return nil
}