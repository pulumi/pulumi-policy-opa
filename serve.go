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
	"fmt"

	"github.com/pkg/errors"
	"google.golang.org/grpc"

	"github.com/pulumi/pulumi/pkg/resource/provider"
	"github.com/pulumi/pulumi/pkg/util/cmdutil"
	"github.com/pulumi/pulumi/pkg/util/logging"
	"github.com/pulumi/pulumi/pkg/util/rpcutil"
	pulumirpc "github.com/pulumi/pulumi/sdk/proto/go"
)

// Serve fires up a Pulumi analyzer provider listening to inbound gRPC traffic,
// and translates calls from Pulumi into actions against the OPA rules in packInfo.
func Serve(pack *policyPack, e *evaler, args []string) error {
	// First inittialize all loggers.
	logging.InitLogging(false, 0, false)
	cmdutil.InitTracing(pack.Name, pack.Name, "")

	// Read the non-flags args and connect to the engine.
	if len(args) == 0 {
		return errors.New("fatal: could not connect to host RPC; missing argument")
	}
	host, err := provider.NewHostClient(args[0])
	if err != nil {
		return errors.Wrapf(err, "fatal: could not connect to host RPC")
	}

	// Create a new gRPC server and listen for and serve incoming connections.
	port, done, err := rpcutil.Serve(0, nil, []func(*grpc.Server) error{
		func(srv *grpc.Server) error {
			analyzer := NewAnalyzer(host, pack, e)
			pulumirpc.RegisterAnalyzerServer(srv, analyzer)
			return nil
		},
	}, nil)
	if err != nil {
		return errors.Wrapf(err, "fatal: could not serve RPC")
	}

	// The plugin protocol requires that we now write out the port we've chosen to listen on.
	fmt.Printf("%d\n", port)

	// Finally, wait for the server to stop serving before returning.
	if err := <-done; err != nil {
		return errors.Wrapf(err, "fatal: plugin exit")
	}

	return nil
}
