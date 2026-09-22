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
	"bufio"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/emptypb"

	pulumirpc "github.com/pulumi/pulumi/sdk/v3/proto/go"
)

// TestLanguageHost_RunPluginLaunchesAnalyzer drives the real binary the way the CLI does: start it as
// `pulumi-language-opa <engine>`, call RunPlugin for a policy pack, then talk Analyzer gRPC to the port it streams.
func TestLanguageHost_RunPluginLaunchesAnalyzer(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	bin := filepath.Join(t.TempDir(), "pulumi-language-opa")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}

	host := exec.CommandContext(ctx, bin, "127.0.0.1:1")
	hostOut, err := host.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Process.Kill(); _ = host.Wait() })

	port, err := bufio.NewReader(hostOut).ReadString('\n')
	if err != nil {
		t.Fatalf("reading language host port: %v", err)
	}
	lang := pulumirpc.NewLanguageRuntimeClient(dial(t, strings.TrimSpace(port)))

	info, err := lang.GetPluginInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Version != VersionString {
		t.Errorf("GetPluginInfo version = %q, want %q", info.Version, VersionString)
	}

	packDir, err := filepath.Abs("../../tests/aws")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := lang.RunPlugin(ctx, &pulumirpc.RunPluginRequest{
		Args: []string{"127.0.0.1:1"},
		Info: &pulumirpc.ProgramInfo{RootDirectory: packDir, ProgramDirectory: packDir, EntryPoint: "."},
		Kind: "analyzer",
	})
	if err != nil {
		t.Fatal(err)
	}

	// The first stdout line from the child analyzer is its port.
	var stdout, stderr strings.Builder
	for !strings.Contains(stdout.String(), "\n") {
		msg, err := stream.Recv()
		if err != nil {
			t.Fatalf("waiting for analyzer port: %v\nstderr: %s", err, stderr.String())
		}
		if msg.GetExitcode() != 0 {
			t.Fatalf("analyzer exited with code %d\nstderr: %s", msg.GetExitcode(), stderr.String())
		}
		stdout.Write(msg.GetStdout())
		stderr.Write(msg.GetStderr())
	}
	analyzerPort, _, _ := strings.Cut(stdout.String(), "\n")

	analyzer := pulumirpc.NewAnalyzerClient(dial(t, strings.TrimSpace(analyzerPort)))
	ai, err := analyzer.GetAnalyzerInfo(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	// The pack version comes from PulumiPolicy.yaml via the CLI, never the plugin build version.
	if ai.Version != "" {
		t.Errorf("GetAnalyzerInfo version = %q, want empty", ai.Version)
	}
	if ai.Name != "aws" || len(ai.Policies) == 0 {
		t.Errorf("GetAnalyzerInfo = name %q with %d policies, want pack \"aws\" with policies", ai.Name, len(ai.Policies))
	}
}

func dial(t *testing.T, port string) *grpc.ClientConn {
	t.Helper()
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
