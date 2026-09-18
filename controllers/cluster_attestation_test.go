package controllers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/client/orm"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	_ "github.com/mattn/go-sqlite3"
	"tcas/apprasisal"
	"tcas/endorsement"
	"tcas/models"
	"tcas/tees"
	"tcas/tees/tdx"
)

type clusterHTTPVerifier struct{ tdx.Verifier }

func (v *clusterHTTPVerifier) VerifyTeeReport(report []byte, _ interface{}) (tees.VerifyTeeResult, error) {
	var result tees.VerifyTeeResult
	err := json.Unmarshal(report, &result)
	return result, err
}

func TestClusterAttestationHTTP(t *testing.T) {
	if err := orm.RegisterDataBase("default", "sqlite3", t.TempDir()+"/cluster.db"); err != nil {
		t.Fatal(err)
	}
	if err := orm.RunSyncdb("default", false, false); err != nil {
		t.Fatal(err)
	}
	clusterID, err := models.PolicyModel.CreateCluster("test-cluster", "another-user")
	if err != nil {
		t.Fatal(err)
	}
	policy := &models.Policy{ClusterId: clusterID, UserId: "another-user", Name: "test", AttestationType: models.ClusterType,
		Rego: base64.StdEncoding.EncodeToString([]byte("package trustnode\nmatch_node { input.trusted_node.tee.tdx_mrtd == \"allowed\" }"))}
	if _, err := models.PolicyModel.AddPolicy(policy); err != nil {
		t.Fatal(err)
	}
	emptyID, err := models.PolicyModel.CreateCluster("empty-cluster", "another-user")
	if err != nil {
		t.Fatal(err)
	}
	oldNonce := apprasisal.GNonceManager
	apprasisal.GNonceManager = apprasisal.NewNonceManager(15)
	nonce, err := apprasisal.GNonceManager.GenerateNonce()
	if err != nil {
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
	tees.Verifiers["tdx"] = &clusterHTTPVerifier{}
	oldCopy := beego.BConfig.CopyRequestBody
	beego.BConfig.CopyRequestBody = true
	t.Cleanup(func() {
		apprasisal.GNonceManager = oldNonce
		endorsement.ECPrivateKey, endorsement.CAJWK = oldKey, oldJWK
		tees.Verifiers["tdx"] = oldVerifier
		beego.BConfig.CopyRequestBody = oldCopy
	})
	router := beego.NewControllerRegister()
	router.Add("/v1/attest/cluster", &ClusterAttestationController{}, beego.WithRouterMethods(&ClusterAttestationController{}, "post:AttestCluster"))
	router.Add("/v1/attest/cluster/node/:cluster_id", &ClusterAttestationController{}, beego.WithRouterMethods(&ClusterAttestationController{}, "post:AttestClusterNode"))
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(nonce.Id)))
	quote, _ := json.Marshal(map[string]interface{}{"tdx_mrtd": "allowed", "tdx_report_data": hex.EncodeToString([]byte(digest))})
	report := fmt.Sprintf(`{"node_id":"node-a","tee":"tdx","tee_report":%q}`, base64.StdEncoding.EncodeToString(quote))
	batch := fmt.Sprintf(`{"mode":"anymatch","cluster_ids":[%q],"nonce":%q,"reports":[%s]}`, clusterID, nonce.Id, report)
	node := fmt.Sprintf(`{"nonce":%q,"report":%s}`, nonce.Id, report)
	for _, tc := range []struct {
		name, method, path, body string
		status                   int
	}{
		{"anonymous cluster success", "POST", "/v1/attest/cluster", batch, http.StatusOK},
		{"anonymous node success", "POST", "/v1/attest/cluster/node/" + clusterID, node, http.StatusOK},
		{"node without nonce", "POST", "/v1/attest/cluster/node/" + clusterID, `{"report":` + report + `}`, http.StatusOK},
		{"unknown cluster", "POST", "/v1/attest/cluster", strings.ReplaceAll(batch, clusterID, "unknown"), http.StatusBadRequest},
		{"unknown node cluster", "POST", "/v1/attest/cluster/node/unknown", node, http.StatusBadRequest},
		{"empty policies", "POST", "/v1/attest/cluster", strings.ReplaceAll(batch, clusterID, emptyID), http.StatusBadRequest},
		{"malformed JSON", "POST", "/v1/attest/cluster", "{", http.StatusBadRequest},
		{"null batch", "POST", "/v1/attest/cluster", "null", http.StatusBadRequest},
		{"null node", "POST", "/v1/attest/cluster/node/" + clusterID, "null", http.StatusBadRequest},
		{"missing report", "POST", "/v1/attest/cluster/node/" + clusterID, "{}", http.StatusBadRequest},
		{"invalid nonce", "POST", "/v1/attest/cluster/node/" + clusterID, strings.ReplaceAll(node, nonce.Id, "unknown"), http.StatusBadRequest},
		{"unsupported mode", "POST", "/v1/attest/cluster", strings.ReplaceAll(batch, "anymatch", "allmatch"), http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			// These endpoints do not authenticate even if an unusable key is sent.
			req.Header.Set("API-KEY", "unused")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code != tc.status {
				t.Fatalf("status %d, want %d: %s", response.Code, tc.status, response.Body.String())
			}
			var result clusterAttestationResponse
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if tc.status == http.StatusOK {
				parsed, err := (&jwt.Parser{ValidMethods: []string{"ES256"}}).Parse(result.Token, func(*jwt.Token) (interface{}, error) { return &key.PublicKey, nil })
				if err != nil || !parsed.Valid || result.Code != "200" {
					t.Fatalf("invalid success response: %+v, %v", result, err)
				}
			} else if result.Token != "" || result.Code == "200" || result.Message == "" {
				t.Fatalf("invalid error response: %+v", result)
			}
		})
	}
}
