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

// Package subfinder encapsulates subdomain enumeration and filtering.
package subfinder

import (
	"certfinder/internal/argparser"
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)



type Subfinder struct {
	args     *argparser.Arguments
	domains   map[string]struct{}
}



func NewSubfinder(args *argparser.Arguments) *Subfinder {
	s := &Subfinder{ args: args }
	return s
}



func (s *Subfinder) Run() (map[string]struct{}, error) {
	fmt.Printf("[+] Looking for %s subdomains\n", s.args.BaseDomain)

	if err := s.runSubfinder(); err != nil {
		return nil, err
	}

	if err := s.pruneDomains(); err != nil {
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
		s.args.BaseDomain,
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



func (s *Subfinder) pruneDomains() error {
	if s.args.DomsToRemove == nil {
		return nil
	}

	re, err := s.sliceToRegex()

	if err != nil {
		return fmt.Errorf("invalid prune regex: %w", err)
	}

	for host := range s.domains {
		if !strings.HasSuffix(host, s.args.BaseDomain) || re.MatchString(host) {
			delete(s.domains, host)
		}
	}

	return nil
}



func (s *Subfinder) sliceToRegex() (*regexp.Regexp, error) {
	if len(s.args.DomsToRemove) == 0 {
		return nil, fmt.Errorf("cannot create regex from an empty slice")
	}

	escapedElements := make([]string, len(s.args.DomsToRemove))
	for i, el := range s.args.DomsToRemove {
		escapedElements[i] = regexp.QuoteMeta(el)
	}

	pattern := "(?:" + strings.Join(escapedElements, "|") + ")"

	return regexp.Compile(pattern)
}