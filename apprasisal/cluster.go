package apprasisal

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"tcas/models"
	"tcas/tees"
	"tcas/token"
	"tcas/util/convertor"
)

// ClusterReport uses the field names from the cluster attestation API. NodeID is
// only required by the batch endpoint and is a caller-supplied correlation ID.
type ClusterReport struct {
	NodeID               string            `json:"node_id,omitempty"`
	Tee                  string            `json:"tee"`
	TeeReport            string            `json:"tee_report"`
	Parameter            interface{}       `json:"parameter,omitempty"`
	TrustedHeteroDevices []json.RawMessage `json:"trusted_hetero_devices,omitempty"`
	RuntimeData          string            `json:"runtime_data,omitempty"`
	RuntimeDate          string            `json:"runtime_date,omitempty"`
	InitData             string            `json:"init_data,omitempty"`
	EventLog             string            `json:"event_log,omitempty"`
}

type ClusterRequest struct {
	Mode       string           `json:"mode"`
	Reports    []*ClusterReport `json:"reports"`
	Nonce      string           `json:"nonce"`
	ClusterIDs []string         `json:"cluster_ids"`
}

type ClusterNodeRequest struct {
	Report *ClusterReport `json:"report"`
	Nonce  string         `json:"nonce"`
}

func (r *ClusterReport) evidence() (*NodeEvidence, error) {
	if r == nil {
		return nil, fmt.Errorf("report is required")
	}
	if r.Tee != "tdx" {
		return nil, fmt.Errorf("only tdx is supported")
	}
	if data, err := base64.StdEncoding.DecodeString(r.TeeReport); err != nil || len(data) == 0 {
		return nil, fmt.Errorf("tee_report must be non-empty base64")
	}
	if len(r.TrustedHeteroDevices) != 0 || r.InitData != "" || r.EventLog != "" {
		return nil, fmt.Errorf("trusted_hetero_devices, init_data and event_log are not supported yet")
	}
	if r.RuntimeData != "" && r.RuntimeDate != "" && r.RuntimeData != r.RuntimeDate {
		return nil, fmt.Errorf("runtime_data and runtime_date must agree")
	}
	runtimeData := r.RuntimeData
	if runtimeData == "" {
		runtimeData = r.RuntimeDate
	}
	if _, err := base64.StdEncoding.DecodeString(runtimeData); err != nil {
		return nil, fmt.Errorf("runtime data must be base64")
	}
	return &NodeEvidence{Tee: r.Tee, TeeReport: r.TeeReport, Parameter: r.Parameter, RuntimeData: runtimeData}, nil
}

func (r *ClusterRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is required")
	}
	if r.Mode != "anymatch" {
		return fmt.Errorf("only mode anymatch is supported")
	}
	if len(r.ClusterIDs) != 1 || strings.TrimSpace(r.ClusterIDs[0]) == "" {
		return fmt.Errorf("cluster_ids must contain exactly one cluster ID")
	}
	if strings.TrimSpace(r.Nonce) == "" {
		return fmt.Errorf("nonce is required")
	}
	if len(r.Reports) == 0 {
		return fmt.Errorf("reports must not be empty")
	}
	seen := make(map[string]bool, len(r.Reports))
	for i, report := range r.Reports {
		if report == nil || strings.TrimSpace(report.NodeID) == "" {
			return fmt.Errorf("reports[%d].node_id is required", i)
		}
		if seen[report.NodeID] {
			return fmt.Errorf("duplicate node_id %q", report.NodeID)
		}
		seen[report.NodeID] = true
		if _, err := report.evidence(); err != nil {
			return fmt.Errorf("node %q: %w", report.NodeID, err)
		}
	}
	return nil
}

func (r *ClusterNodeRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is required")
	}
	_, err := r.Report.evidence()
	return err
}

type ClusterPolicyInfo struct {
	ClusterID    string `json:"cluster_id"`
	PoliciesHash string `json:"policies_hash"`
	PolicyID     string `json:"policy_id,omitempty"`
	PolicyHash   string `json:"policy_hash,omitempty"`
}

type ClusterTrustedNode struct {
	Tee                  tees.VerifyTeeResult   `json:"tee"`
	TrustedHeteroDevices []tees.VerifyTeeResult `json:"trusted_hetero_devices"`
}

type ClusterNodeDetail struct {
	NodeID string `json:"node_id"`
	ClusterTrustedNode
	AttesterInfo *AttesterInfo       `json:"attester_info,omitempty"`
	PolicyInfos  []ClusterPolicyInfo `json:"policy_infos"`
}

type clusterPolicy struct {
	info  ClusterPolicyInfo
	query rego.PreparedEvalQuery
}

// Compile the whole policy snapshot before evaluating nodes. Invalid policies
// are configuration errors, not ordinary non-matches, even in anymatch mode.
func prepareClusterPolicies(ctx context.Context, clusterID string, policies []*models.Policy) ([]clusterPolicy, string, error) {
	if len(policies) == 0 {
		return nil, "", fmt.Errorf("cluster has no policies")
	}
	snapshot := append([]*models.Policy(nil), policies...)
	for _, p := range snapshot {
		if p == nil || p.Id == "" || p.ClusterId != clusterID || p.AttestationType != models.ClusterType {
			return nil, "", fmt.Errorf("invalid cluster policy")
		}
	}
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].Id < snapshot[j].Id })
	type policyDigest struct {
		ID   string `json:"policy_id"`
		Hash string `json:"policy_hash"`
	}
	digests := make([]policyDigest, 0, len(snapshot))
	prepared := make([]clusterPolicy, 0, len(snapshot))
	for _, p := range snapshot {
		source, err := base64.StdEncoding.DecodeString(p.Rego)
		if err != nil {
			return nil, "", fmt.Errorf("policy %s: invalid base64", p.Id)
		}
		// The design's Rego example uses every without an explicit import.
		module, err := ast.ParseModuleWithOpts("policy.rego", string(source), ast.ParserOptions{
			FutureKeywords: []string{"every"},
		})
		if err != nil {
			return nil, "", fmt.Errorf("policy %s: %w", p.Id, err)
		}
		if module == nil {
			return nil, "", fmt.Errorf("policy %s: empty Rego module", p.Id)
		}
		query, err := rego.New(
			rego.Query("data.trustnode.match_node"),
			rego.ParsedModule(module),
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
		if err != nil {
			return nil, "", fmt.Errorf("policy %s: %w", p.Id, err)
		}
		// Match the existing policy model's SHA-256 of the base64 Rego text.
		hash := fmt.Sprintf("%x", sha256.Sum256([]byte(p.Rego)))
		digests = append(digests, policyDigest{ID: p.Id, Hash: hash})
		prepared = append(prepared, clusterPolicy{
			info:  ClusterPolicyInfo{ClusterID: clusterID, PolicyID: p.Id, PolicyHash: hash},
			query: query,
		})
	}
	encoded, err := json.Marshal(digests)
	if err != nil {
		return nil, "", err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(encoded))
	for i := range prepared {
		prepared[i].info.PoliciesHash = hash
	}
	return prepared, hash, nil
}

func evaluateClusterNode(ctx context.Context, report *ClusterReport, nonce string, policies []clusterPolicy) (*ClusterNodeDetail, error) {
	evidence, err := report.evidence()
	if err != nil {
		return nil, err
	}
	verified, err := NodeVerify(evidence)
	if err != nil {
		return nil, err
	}
	attester, err := UserDataCheck(verified, nonce, evidence.RuntimeData)
	if err != nil {
		return nil, err
	}
	node := &ClusterNodeDetail{
		NodeID:             report.NodeID,
		ClusterTrustedNode: ClusterTrustedNode{Tee: verified.Tee, TrustedHeteroDevices: verified.TrustDevice},
		AttesterInfo:       attester,
		PolicyInfos:        make([]ClusterPolicyInfo, 0),
	}
	input := map[string]interface{}{"trusted_node": node.ClusterTrustedNode}
	for _, policy := range policies {
		results, err := policy.query.Eval(ctx, rego.EvalInput(input))
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", policy.info.PolicyID, err)
		}
		if len(results) == 0 {
			continue
		}
		if len(results) != 1 || len(results[0].Expressions) != 1 {
			return nil, fmt.Errorf("policy %s: invalid match_node result", policy.info.PolicyID)
		}
		match, ok := results[0].Expressions[0].Value.(bool)
		if !ok {
			return nil, fmt.Errorf("policy %s: match_node must be boolean", policy.info.PolicyID)
		}
		if match {
			node.PolicyInfos = append(node.PolicyInfos, policy.info)
		}
	}
	if len(node.PolicyInfos) == 0 {
		return nil, fmt.Errorf("node does not match any cluster policy")
	}
	return node, nil
}

func ClusterAppraisal(ctx context.Context, request *ClusterRequest, policies []*models.Policy) (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}
	prepared, hash, err := prepareClusterPolicies(ctx, request.ClusterIDs[0], policies)
	if err != nil {
		return "", err
	}
	details := make([]*ClusterNodeDetail, 0, len(request.Reports))
	for _, report := range request.Reports {
		node, err := evaluateClusterNode(ctx, report, request.Nonce, prepared)
		if err != nil {
			return "", fmt.Errorf("node %q: %w", report.NodeID, err)
		}
		details = append(details, node)
	}
	// Normalize to JSON maps so keys are sorted at every level, independently
	// of Go struct field order. Clients can reproduce the hash after parsing.
	detailMap, err := convertor.AnyToMap(struct {
		Details []*ClusterNodeDetail `json:"cluster_detail"`
	}{details})
	if err != nil {
		return "", err
	}
	detailJSON, err := json.Marshal(detailMap)
	if err != nil {
		return "", err
	}
	return token.GenerateToken(map[string]interface{}{
		"ver":          "1.0.0",
		"mode":         request.Mode,
		"policy_infos": []ClusterPolicyInfo{{ClusterID: request.ClusterIDs[0], PoliciesHash: hash}},
		"trusted_cluster": map[string]interface{}{
			"trusted_cluster_hash": fmt.Sprintf("%x", sha256.Sum256(detailJSON)),
			"cluster_detail":       detailMap["cluster_detail"],
		},
	})
}

func ClusterNodeAppraisal(ctx context.Context, clusterID string, request *ClusterNodeRequest, policies []*models.Policy) (string, error) {
	if strings.TrimSpace(clusterID) == "" {
		return "", fmt.Errorf("cluster_id is required")
	}
	if err := request.Validate(); err != nil {
		return "", err
	}
	prepared, _, err := prepareClusterPolicies(ctx, clusterID, policies)
	if err != nil {
		return "", err
	}
	node, err := evaluateClusterNode(ctx, request.Report, request.Nonce, prepared)
	if err != nil {
		return "", err
	}
	claims, err := convertor.AnyToMap(struct {
		Version      string              `json:"ver"`
		AttesterInfo *AttesterInfo       `json:"attester_info,omitempty"`
		PolicyInfos  []ClusterPolicyInfo `json:"policy_infos"`
		TrustedNode  ClusterTrustedNode  `json:"trusted_node"`
	}{"1.0.0", node.AttesterInfo, node.PolicyInfos, node.ClusterTrustedNode})
	if err != nil {
		return "", err
	}
	return token.GenerateToken(claims)
}
