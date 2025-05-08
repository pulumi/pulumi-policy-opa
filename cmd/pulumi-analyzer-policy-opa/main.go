// Copyright 2019, Pulumi Corporation.
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
	"github.com/pulumi/pulumi/pkg/util/logging"
	pulumirpc "github.com/pulumi/pulumi/sdk/proto/go"
	"os"

	"github.com/pulumi/pulumi/pkg/util/cmdutil"
)

func main() {

	logging.InitLogging(false, 0, false)

	rc, err := rpcCmd.NewRpcCmd(&rpcCmd.RpcCmdConfig{})
	if err != nil {
		cmdutil.Exit(err)
	}

	var dumpInfo bool
	rc.Flag.BoolVar(&dumpInfo, "get-plugin-info", false, "dump plugin info as JSON to stdout")

	pack, e, err := loadPolicyPack(rpc.PluginPath)
	if err != nil {
		cmdutil.Exit(err)
	}
	rc.TracingName = pack.Name
	rc.RootSpanName = pack.Name

	if dumpInfo {
		if err := json.NewEncoder(os.Stdout).Encode(pack); err != nil {
			cmdutil.ExitError(err.Error())
		}
		os.Exit(0)
	}

	rc.Run(func(srv *grpc.Server) error {
		analyzer := NewAnalyzer(host, pack, e)
		pulumirpc.RegisterAnalyzerServer(srv, analyzer)
		return nil
	}, func() {})
}
