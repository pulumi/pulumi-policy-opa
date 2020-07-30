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

func (e *evaler) evalPolicyPack(ctx context.Context, pack *policyPack, input interface{}) ([]evalPolicyResult, error) {
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
				if ae, ok := expr.Value.([]interface{}); ok && len(ae) > 0 {
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
