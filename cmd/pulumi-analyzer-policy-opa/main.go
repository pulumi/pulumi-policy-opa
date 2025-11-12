// Copyright 2025, Pulumi Corporation.
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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/contract"
)

func main() {
	// Enable overriding the rules location and/or dumping plugin info.
	flags := flag.NewFlagSet("tf-provider-flags", flag.ContinueOnError)
	version := flags.Bool("version", false, "print version information")
	dumpInfo := flags.Bool("get-plugin-info", false, "dump plugin info as JSON to stdout")
	contract.IgnoreError(flags.Parse(os.Args[1:]))
	args := flags.Args()

	if *version {
		fmt.Println(VersionString)
		os.Exit(0)
	}

	if len(args) < 1 {
		cmdutil.ExitError("missing required argument: policy pack directory path")
	}

	pack, e, err := loadPolicyPack(args[0])
	if err != nil {
		cmdutil.ExitError(err.Error())
	}

	if *dumpInfo {
		if err := json.NewEncoder(os.Stdout).Encode(pack); err != nil {
			cmdutil.ExitError(err.Error())
		}
		os.Exit(0)
	}

	if err := Serve(pack, e, args); err != nil {
		cmdutil.ExitError(err.Error())
	}
}
