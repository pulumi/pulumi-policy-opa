// Copyright 2026, Pulumi Corporation.
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
	"os"

	"github.com/pulumi/pulumi/sdk/v3/go/common/util/cmdutil"
)

func main() {
	args := os.Args[1:]

	// Launched as `pulumi-language-opa <engineAddr>`: serve the language runtime, whose
	// RunPlugin re-execs this binary with [engineAddr, packDir] to run the analyzer below.
	if len(args) == 1 {
		if err := serveLanguageHost(); err != nil {
			cmdutil.ExitError(err.Error())
		}
		return
	}

	if len(args) < 2 {
		cmdutil.ExitError("missing required arguments: host and policy pack directory path")
	}

	pack, e, err := loadPolicyPack(args[1])
	if err != nil {
		cmdutil.ExitError(err.Error())
	}

	if err := Serve(pack, e, args); err != nil {
		cmdutil.ExitError(err.Error())
	}
}
