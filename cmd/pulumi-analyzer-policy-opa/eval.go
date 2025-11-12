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
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/pkg/errors"
)

type evaler struct {
	c *ast.Compiler
}

func (e *evaler) evalPolicyPack(
	ctx context.Context,
	pack *policyPack,
	input any,
) ([]evalPolicyResult, error) {
	var results []evalPolicyResult

	for _, rule := range pack.Policies {
		// Build a rego object that can be evaluated.
		robj := rego.New(
			rego.Query(fmt.Sprintf("data.%s.%s", pack.Name, rule.Name)),
			rego.Compiler(e.c),
			rego.Input(input),
		)

		resultSet, err := robj.Eval(ctx)
		if err != nil {
			return nil, errors.Wrapf(err, "evaluating rule %s.%s", pack.Name, rule.Name)
		}

		for _, result := range resultSet {
			for _, expr := range result.Expressions {
				if ae, ok := expr.Value.([]any); ok && len(ae) > 0 {
					for _, v := range ae {
						results = append(results, evalPolicyResult{
							pack:  pack.Name,
							rule:  rule.Name,
							msg:   v.(string),
							level: rule.Level,
						})
					}
				}
			}
		}
	}

	return results, nil
}

type evalPolicyResult struct {
	pack  string
	rule  string
	msg   string
	level enforcementLevel
}
