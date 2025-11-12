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
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/pulumi/pulumi/sdk/v3/go/common/resource/plugin"
	"github.com/pulumi/pulumi/sdk/v3/go/common/util/rpcutil"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
)

// Serve fires up a Pulumi analyzer provider listening to inbound gRPC traffic,
// and translates calls from Pulumi into actions against the OPA rules in packInfo.
func Serve(
	pack *policyPack,
	e *evaler,
	args []string,
) error {
	// Create an analyzer implementation
	analyzer := NewAnalyzer(pack, e)

	// Wrap it with the gRPC server
	analyzerServer := plugin.NewAnalyzerServer(analyzer)

	// Create a new gRPC server and listen for and serve incoming connections.
	handle, err := rpcutil.ServeWithOptions(rpcutil.ServeOptions{
		Init: func(srv *grpc.Server) error {
			pulumirpc.RegisterAnalyzerServer(srv, analyzerServer)
			return nil
		},
	})
	if err != nil {
		return errors.Wrapf(err, "fatal: could not serve RPC")
	}

	// The plugin protocol requires that we now write out the port we've chosen to listen on.
	fmt.Printf("%d\n", handle.Port)

	// Finally, wait for the server to stop serving before returning.
	if err := <-handle.Done; err != nil {
		return errors.Wrapf(err, "fatal: plugin exit")
	}

	return nil
}
