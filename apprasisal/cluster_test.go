package apprasisal

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/beego/beego/v2/client/orm"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	_ "github.com/mattn/go-sqlite3"
	"tcas/endorsement"
	"tcas/models"
	"tcas/tees"
	"tcas/tees/tdx"
)

// Only hardware signature verification is substituted; nonce storage, TDX
// report-data decoding, OPA evaluation and ES256 signing use real code.
type clusterTestVerifier struct {
	tdx.Verifier
	calls int
}

func (v *clusterTestVerifier) VerifyTeeReport(report []byte, _ interface{}) (tees.VerifyTeeResult, error) {
	v.calls++
	var result tees.VerifyTeeResult
	if err := json.Unmarshal(report, &result); err != nil {
		return nil, fmt.Errorf("invalid hardware signature")
	}
	return result, nil
}

func testClusterReport(id, measurement, nonce, runtimeData string) *ClusterReport {
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(nonce+runtimeData)))
	raw, _ := json.Marshal(map[string]interface{}{
		"tdx_mrtd":        measurement,
		"tdx_report_data": hex.EncodeToString([]byte(digest)),
	})
	return &ClusterReport{NodeID: id, Tee: "tdx", TeeReport: base64.StdEncoding.EncodeToString(raw), RuntimeData: runtimeData}
}

func testClusterPolicy(id, source string) *models.Policy {
	encoded := base64.StdEncoding.EncodeToString([]byte(source))
	return &models.Policy{Id: id, ClusterId: "cluster", AttestationType: models.ClusterType,
		Rego: encoded, Hash: fmt.Sprintf("%x", sha256.Sum256([]byte(encoded)))}
}

func TestClusterAttestation(t *testing.T) {
	if err := orm.RegisterDataBase("default", "sqlite3", t.TempDir()+"/cluster.db"); err != nil {
		t.Fatal(err)
	}
	if err := orm.RunSyncdb("default", false, false); err != nil {
		t.Fatal(err)
	}
	oldNonce := GNonceManager
	GNonceManager = NewNonceManager(15)
	nonce, err := GNonceManager.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	expired, err := GNonceManager.GenerateNonce()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := orm.NewOrm().Raw("UPDATE t_nonce SET create_time = ? WHERE id = ?", time.Now().Add(-time.Hour), expired.Id).Exec(); err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwk.New(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, oldJWK := endorsement.ECPrivateKey, endorsement.CAJWK
	endorsement.ECPrivateKey, endorsement.CAJWK = key, jwkKey
	oldVerifier := tees.Verifiers["tdx"]
	verifier := &clusterTestVerifier{}
	tees.Verifiers["tdx"] = verifier
	t.Cleanup(func() {
		GNonceManager = oldNonce
		endorsement.ECPrivateKey, endorsement.CAJWK = oldKey, oldJWK
		tees.Verifiers["tdx"] = oldVerifier
	})
	ctx := context.Background()
	policies := []*models.Policy{
		testClusterPolicy("a", `package trustnode
default match_node := false
match_node { input.trusted_node.tee.tdx_mrtd == "a" }`),
		testClusterPolicy("b", `package trustnode
default match_node := false
match_node {
 input.trusted_node.tee.tdx_mrtd == "b"
 every d in input.trusted_node.trusted_hetero_devices { d.valid == true }
}`),
	}
	request := func() *ClusterRequest {
		return &ClusterRequest{Mode: "anymatch", ClusterIDs: []string{"cluster"}, Nonce: nonce.Id,
			Reports: []*ClusterReport{testClusterReport("node-a", "a", nonce.Id, ""), testClusterReport("node-b", "b", nonce.Id, "")}}
	}
	parse := func(t *testing.T, signed string) jwt.MapClaims {
		t.Helper()
		parsed, err := (&jwt.Parser{ValidMethods: []string{"ES256"}}).Parse(signed, func(*jwt.Token) (interface{}, error) { return &key.PublicKey, nil })
		if err != nil || !parsed.Valid {
			t.Fatalf("invalid signed token: %v", err)
		}
		return parsed.Claims.(jwt.MapClaims)
	}
	t.Run("all nodes match independently and token hash is reproducible", func(t *testing.T) {
		verifier.calls = 0
		signed, err := ClusterAppraisal(ctx, request(), policies)
		if err != nil {
			t.Fatal(err)
		}
		if verifier.calls != 2 {
			t.Fatalf("verified %d times, want once per report", verifier.calls)
		}
		claims := parse(t, signed)
		cluster := claims["trusted_cluster"].(map[string]interface{})
		details := cluster["cluster_detail"].([]interface{})
		if len(details) != 2 || claims["mode"] != "anymatch" || claims["ver"] != "1.0.0" {
			t.Fatalf("unexpected claims: %v", claims)
		}
		for i, id := range []string{"a", "b"} {
			node := details[i].(map[string]interface{})
			matched := node["policy_infos"].([]interface{})
			if len(matched) != 1 || matched[0].(map[string]interface{})["policy_id"] != id {
				t.Fatalf("unexpected matches: %v", matched)
			}
			if node["attester_info"].(map[string]interface{})["verify_nonce"] != nonce.Id {
				t.Fatal("missing verified nonce")
			}
		}
		encoded, _ := json.Marshal(map[string]interface{}{"cluster_detail": details})
		if cluster["trusted_cluster_hash"] != fmt.Sprintf("%x", sha256.Sum256(encoded)) {
			t.Fatal("cluster detail hash mismatch")
		}
		if _, exists := cluster["trusted_cluster_url"]; exists {
			t.Fatal("unexpected URL without a detail endpoint")
		}
	})
	t.Run("different nodes may match the same policy", func(t *testing.T) {
		r := request()
		r.Reports[1] = testClusterReport("node-b", "a", nonce.Id, "")
		if _, err := ClusterAppraisal(ctx, r, policies); err != nil {
			t.Fatal(err)
		}
	})
	for _, tc := range []struct {
		name string
		edit func(*ClusterRequest)
		want string
	}{
		{"unmatched second node", func(r *ClusterRequest) { r.Reports[1] = testClusterReport("node-b", "c", nonce.Id, "") }, "node-b"},
		{"bad signature", func(r *ClusterRequest) { r.Reports[1].TeeReport = "YmFk" }, "hardware signature"},
		{"unknown nonce", func(r *ClusterRequest) { r.Nonce = "unknown" }, "not exist"},
		{"expired nonce", func(r *ClusterRequest) { r.Nonce = expired.Id }, "expired"},
		{"wrong nonce binding", func(r *ClusterRequest) { r.Reports[1] = testClusterReport("node-b", "b", "wrong", "") }, "userData"},
		{"runtime data tampering", func(r *ClusterRequest) { r.Reports[0].RuntimeData = "eA==" }, "userData"},
		{"allmatch rejected", func(r *ClusterRequest) { r.Mode = "allmatch" }, "anymatch"},
		{"multiple clusters rejected", func(r *ClusterRequest) { r.ClusterIDs = []string{"cluster", "other"} }, "exactly one"},
		{"missing clusters", func(r *ClusterRequest) { r.ClusterIDs = nil }, "exactly one"},
		{"duplicate node ID", func(r *ClusterRequest) { r.Reports[1].NodeID = "node-a" }, "duplicate"},
		{"missing node ID", func(r *ClusterRequest) { r.Reports[1].NodeID = "" }, "node_id"},
		{"null report", func(r *ClusterRequest) { r.Reports[0] = nil }, "node_id"},
		{"empty reports", func(r *ClusterRequest) { r.Reports = nil }, "reports"},
		{"missing nonce", func(r *ClusterRequest) { r.Nonce = "" }, "nonce"},
		{"unsupported TEE", func(r *ClusterRequest) { r.Reports[0].Tee = "virtcca" }, "only tdx"},
		{"empty quote", func(r *ClusterRequest) { r.Reports[0].TeeReport = "" }, "base64"},
		{"malformed quote encoding", func(r *ClusterRequest) { r.Reports[0].TeeReport = "%%%" }, "base64"},
		{"runtime alias conflict", func(r *ClusterRequest) { r.Reports[0].RuntimeData = "YQ=="; r.Reports[0].RuntimeDate = "Yg==" }, "agree"},
		{"bad runtime encoding", func(r *ClusterRequest) { r.Reports[0].RuntimeDate = "%%%" }, "base64"},
		{"unsupported init data", func(r *ClusterRequest) { r.Reports[0].InitData = "YQ==" }, "not supported"},
		{"unsupported event log", func(r *ClusterRequest) { r.Reports[0].EventLog = "log" }, "not supported"},
		{"unsupported peripheral", func(r *ClusterRequest) {
			r.Reports[0].TrustedHeteroDevices = []json.RawMessage{json.RawMessage(`{"type":"nvidia"}`)}
		}, "not supported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request()
			tc.edit(r)
			signed, err := ClusterAppraisal(ctx, r, policies)
			if signed != "" || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want rejection containing %q, got token=%q err=%v", tc.want, signed, err)
			}
		})
	}
	t.Run("node endpoint runtime alias and all matching policies", func(t *testing.T) {
		runtimeData := base64.StdEncoding.EncodeToString([]byte(`{"key":"value"}`))
		r := testClusterReport("", "a", nonce.Id, runtimeData)
		r.RuntimeDate, r.RuntimeData = r.RuntimeData, ""
		extra := testClusterPolicy("also-a", "package trustnode\nmatch_node := true")
		signed, err := ClusterNodeAppraisal(ctx, "cluster", &ClusterNodeRequest{Report: r, Nonce: nonce.Id}, append(policies, extra))
		if err != nil {
			t.Fatal(err)
		}
		claims := parse(t, signed)
		if len(claims["policy_infos"].([]interface{})) != 2 || claims["trusted_node"] == nil {
			t.Fatalf("unexpected node claims: %v", claims)
		}
		attester := claims["attester_info"].(map[string]interface{})
		if attester["runtimedata_json"].(map[string]interface{})["key"] != "value" {
			t.Fatal("runtime JSON missing")
		}
	})
	t.Run("node nonce optional", func(t *testing.T) {
		signed, err := ClusterNodeAppraisal(ctx, "cluster", &ClusterNodeRequest{Report: testClusterReport("", "a", "", "")}, policies)
		if err != nil {
			t.Fatal(err)
		}
		claims := parse(t, signed)
		if _, exists := claims["attester_info"]; exists {
			t.Fatal("must not claim nonce verification without a nonce")
		}
	})
	t.Run("empty policies rejected", func(t *testing.T) {
		if signed, err := ClusterAppraisal(ctx, request(), nil); signed != "" || err == nil {
			t.Fatal("empty policy group accepted")
		}
	})
	for _, source := range []string{
		"package trustnode\nmatch_node :=",          // malformed Rego
		"package trustnode\nmatch_node := \"true\"", // non-boolean
		"package trustnode\nmatch_node := false",
		"package trustnode\nother := true", // undefined query
		"package trustnode\nmatch_node { input.missing == true }",
	} {
		t.Run("reject policy "+source, func(t *testing.T) {
			signed, err := ClusterNodeAppraisal(ctx, "cluster", &ClusterNodeRequest{Report: testClusterReport("", "a", "", "")}, []*models.Policy{testClusterPolicy("bad", source)})
			if signed != "" || err == nil {
				t.Fatal("invalid or non-matching policy accepted")
			}
		})
	}
	t.Run("invalid policy cannot hide behind a matching policy", func(t *testing.T) {
		bad := testClusterPolicy("bad", "package trustnode\nmatch_node :=")
		if signed, err := ClusterAppraisal(ctx, request(), append(policies, bad)); signed != "" || err == nil {
			t.Fatal("invalid policy ignored")
		}
	})
	t.Run("policy hash stable across database ordering", func(t *testing.T) {
		_, forward, err := prepareClusterPolicies(ctx, "cluster", policies)
		if err != nil {
			t.Fatal(err)
		}
		_, reverse, err := prepareClusterPolicies(ctx, "cluster", []*models.Policy{policies[1], policies[0]})
		if err != nil || forward != reverse {
			t.Fatalf("unstable policy hash: %s %s %v", forward, reverse, err)
		}
		changed := testClusterPolicy("b", "package trustnode\nmatch_node := true")
		_, newHash, err := prepareClusterPolicies(ctx, "cluster", []*models.Policy{policies[0], changed})
		if err != nil || newHash == forward {
			t.Fatalf("policy update did not change hash: %v", err)
		}
	})
}
