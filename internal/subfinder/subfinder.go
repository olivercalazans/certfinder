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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)


const (
	Bin     = "subfinder"
	Timeout = 300 * time.Second
)



type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}



func Run(baseDomain string) (*Result, string) {
	fmt.Printf("[+] Running subfinder: %s\n", baseDomain)

	ctx, cancel := context.WithTimeout(context.Background(), Timeout)
	defer cancel()

	cmd := exec.CommandContext(
		ctx, Bin,
		"-d", baseDomain,
		"-silent",
		"-json",
		"-all",
		"-timeout", "30",
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return nil, "subfinder timeout. It was not able to get domain list"
	}
	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, "subfinder command not found"
		}

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &Result{
				Stdout:   stdout.String(),
				Stderr:   stderr.String(),
				ExitCode: exitErr.ExitCode(),
			}, ""
		}
		
		return nil, fmt.Sprintf("unknown error while executing subfinder: %v", err)
	}

	return &Result{
		Stdout:   stdout.String(),
		Stderr:   stderr.String(),
		ExitCode: 0,
	}, ""
}



func Prune(proc *Result, removePattern, baseDomain string) (map[string]struct{}, error) {
	re, err := regexp.Compile(removePattern)
	
	if err != nil {
		return nil, fmt.Errorf("invalid prune regex: %w", err)
	}

	out := make(map[string]struct{})

	for _, line := range strings.Split(proc.Stdout, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var obj struct {
			Host string `json:"host"`
		}
		
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}

		host := strings.ToLower(strings.TrimSpace(obj.Host))
		
		if host == "" || !strings.HasSuffix(host, baseDomain) {
			continue
		}
		
		if re.MatchString(host) {
			continue
		}

		out[host] = struct{}{}
	}

	return out, nil
}