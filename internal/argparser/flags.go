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

package argparser

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"
)


type parsedArgs struct {
	baseDomain    string
	domsToRemove  []string
}



func (ap *ArgParser) createArgs() {
	ap.parser = pflag.NewFlagSet("certfinder", pflag.ContinueOnError)
	ap.parser.SortFlags = false
	
	ap.parser.SetInterspersed(true)

	ap.parser.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: certfinder [options]\n\nDump a git repository from a website.\n\nOptions:\n")
		ap.parser.PrintDefaults()
	}

	ap.parser.StringVarP(&ap.baseDomain, "domain", "d","", "Base URL (required)")
	ap.parser.StringArrayVarP(&ap.domsToRemove, "remove", "r", nil, "Drop domains with one of the informed strings")
}