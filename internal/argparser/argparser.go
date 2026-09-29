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
	"certfinder/internal/display"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/pflag"
)



type Arguments struct {
	BaseDomain    string
	DomsToRemove  []string
}



type ArgParser struct {
	args     *Arguments
	parser   *pflag.FlagSet
	errList   []error
	parsedArgs
}



func NewParser() *ArgParser {
	return &ArgParser{
		errList: make([]error, 0),
	}
}



func (ap *ArgParser) GetArgs() *Arguments {
	ap.createArgs()

	if err := ap.parser.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, pflag.ErrHelp) {
			os.Exit(0)
		}
	}

	args := &Arguments{
		BaseDomain   : ap.validBaseDomain(),
		DomsToRemove : ap.domsToRemove,
	}

	ap.displayError()
	return args
}



func (ap *ArgParser) addErr(err error) {
	ap.errList = append(ap.errList, err)
}



func (ap *ArgParser) displayError() {
	if len(ap.errList) <= 0 {
		return
	} 

	for i, err := range ap.errList {
		fmt.Printf("%d. %s\n",i+1 , err.Error())
	}
	fmt.Printf("\n")

	display.Fatal(fmt.Errorf("Error during argument parsing"))
}