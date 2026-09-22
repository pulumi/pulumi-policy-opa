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
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/pulumi/pulumi/sdk/v3/go/common/util/rpcutil"
	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
)

// languageHost is a thin Pulumi language runtime for `runtime: opa` policy packs. Its only real job is
// RunPlugin, which re-execs this same binary in analyzer mode, so the analyzer is bundled by construction.
type languageHost struct {
	pulumirpc.UnimplementedLanguageRuntimeServer
}

func (languageHost) GetPluginInfo(context.Context, *emptypb.Empty) (*pulumirpc.PluginInfo, error) {
	return &pulumirpc.PluginInfo{Version: VersionString}, nil
}

func (languageHost) Handshake(
	context.Context, *pulumirpc.LanguageHandshakeRequest,
) (*pulumirpc.LanguageHandshakeResponse, error) {
	return &pulumirpc.LanguageHandshakeResponse{}, nil
}

// InstallDependencies is a no-op: .rego policy packs have no dependencies.
func (languageHost) InstallDependencies(
	*pulumirpc.InstallDependenciesRequest, pulumirpc.LanguageRuntime_InstallDependenciesServer,
) error {
	return nil
}

func (languageHost) GetRequiredPlugins(
	context.Context, *pulumirpc.GetRequiredPluginsRequest,
) (*pulumirpc.GetRequiredPluginsResponse, error) {
	return &pulumirpc.GetRequiredPluginsResponse{}, nil
}

func (languageHost) GetRequiredPackages(
	context.Context, *pulumirpc.GetRequiredPackagesRequest,
) (*pulumirpc.GetRequiredPackagesResponse, error) {
	return &pulumirpc.GetRequiredPackagesResponse{}, nil
}

func (languageHost) GetProgramDependencies(
	context.Context, *pulumirpc.GetProgramDependenciesRequest,
) (*pulumirpc.GetProgramDependenciesResponse, error) {
	return &pulumirpc.GetProgramDependenciesResponse{}, nil
}

func (languageHost) About(context.Context, *pulumirpc.AboutRequest) (*pulumirpc.AboutResponse, error) {
	return &pulumirpc.AboutResponse{}, nil
}

// RunPlugin starts the analyzer as a child process, mirroring how the CLI execs
// pulumi-analyzer-policy-opa directly: args [engineAddr, ".", -k=v...] with the pack dir as cwd.
// The child's stdout is streamed verbatim so its first line (the port) reaches the engine.
func (languageHost) RunPlugin(req *pulumirpc.RunPluginRequest, server pulumirpc.LanguageRuntime_RunPluginServer) error {
	if len(req.Args) == 0 || req.Info == nil {
		return errors.New("RunPlugin requires the engine address argument and program info")
	}

	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locating analyzer executable: %w", err)
	}

	args := []string{req.Args[0], "."}
	for k, v := range req.Info.GetOptions().AsMap() {
		if vstr := fmt.Sprintf("%v", v); vstr != "" {
			args = append(args, fmt.Sprintf("-%s=%s", k, vstr))
		}
	}

	closer, stdout, stderr, err := rpcutil.MakeRunPluginStreams(server, false)
	if err != nil {
		return err
	}
	defer func() { _ = closer.Close() }() // best effort; the explicit Close below reports errors

	cmd := exec.CommandContext(server.Context(), self, args...)
	cmd.Dir = req.Info.ProgramDirectory
	cmd.Env = append(os.Environ(), req.Env...)
	cmd.Stdout, cmd.Stderr = stdout, stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return fmt.Errorf("running analyzer: %w", err)
		}
		if err := server.Send(&pulumirpc.RunPluginResponse{
			Output: &pulumirpc.RunPluginResponse_Exitcode{Exitcode: int32(exitErr.ExitCode())}, //nolint:gosec
		}); err != nil {
			return err
		}
	}

	return closer.Close()
}

// serveLanguageHost serves the language runtime over gRPC and follows the plugin protocol of
// printing the chosen port on stdout.
func serveLanguageHost() error {
	handle, err := rpcutil.ServeWithOptions(rpcutil.ServeOptions{
		Init: func(srv *grpc.Server) error {
			pulumirpc.RegisterLanguageRuntimeServer(srv, languageHost{})
			return nil
		},
	})
	if err != nil {
		return fmt.Errorf("fatal: could not serve RPC: %w", err)
	}

	fmt.Printf("%d\n", handle.Port)

	if err := <-handle.Done; err != nil {
		return fmt.Errorf("fatal: plugin exit: %w", err)
	}
	return nil
}
