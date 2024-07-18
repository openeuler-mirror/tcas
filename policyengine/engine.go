package policyengine

import (
	"context"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

type PolicyExecutor struct {
	query string
	rego  *rego.Rego
}

func NewPolicyExecutor(query string, policy string) *PolicyExecutor {
	r := rego.New(
		rego.Query(query),
		rego.Module("policy", policy),
	)

	return &PolicyExecutor{
		query: query,
		rego:  r,
	}
}

func (pe *PolicyExecutor) Evaluate(input interface{}) (rego.ResultSet, error) {
	query, err := pe.rego.PrepareForEval(context.Background())
	if err != nil {
		return nil, err
	}

	resultSet, err := query.Eval(context.Background(), rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	if len(resultSet) > 0 {
		return resultSet, nil
	}
	return nil, fmt.Errorf("no result found")
}
