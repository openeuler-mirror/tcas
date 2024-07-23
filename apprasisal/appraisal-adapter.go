package apprasisal

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/sirupsen/logrus"
	"tcas/models"
	"tcas/policyengine"
	"tcas/tees"
	"tcas/token"
)

type TrustDeviceReport struct {
	DeviceType   string      `json:"type"`
	DeviceReport string      `json:"device_report"`
	Parameter    interface{} `json:"parameter"`
}

type NodeEvidence struct {
	Tee         string               `json:"tee"`
	TeeReport   string               `json:"tee_report"`
	Parameter   interface{}          `json:"parameter"`
	TrustDevice []*TrustDeviceReport `json:"trust_devices"`
	RuntimeData interface{}          `json:"runtime_data"`
	InitData    string               `json:"init_data"`
	EventLog    string               `json:"event_log"`
}

type NodeAttestInfo struct {
	Report    *NodeEvidence `json:"report"`
	Nonce     string        `json:"nonce"`
	PolicyIds []string      `json:"policy_ids"`
}

type ClusterAttestInfo struct {
	Reports   []*NodeEvidence `json:"reports"`
	Nonce     string          `json:"nonce"`
	PolicyIds []string        `json:"policy_ids"`
}

type TrustNodeVerifiedResult struct {
	Tee         tees.VerifyTeeResult   `json:"tee"`
	TrustDevice []tees.VerifyTeeResult `json:"trust_device"`
}

type TrustNodeClaims struct {
	TrustNode    *TrustNodeVerifiedResult `json:"trust_node"`
	PolicyInfos  []*models.Policy         `json:"policy_info"`
	AttesterInfo interface{}              `json:"attester_info"`
}

type TrustClusterClaims struct {
	TrustNodes   []*TrustNodeVerifiedResult
	PolicyInfos  []*models.Policy
	AttesterInfo interface{}
}

func UserDataCheck(attestResult tees.VerifyTeeResult, nonce, runtimeData string) error {
	if nonce == "" && runtimeData == "" {
		logrus.Info("skip user data check")
		return nil
	}

	if tee, existed := attestResult["type"]; existed {
		teeType := fmt.Sprintf("%s", tee)
		if !tees.IsVerifierExists(teeType) {
			return fmt.Errorf("tee type [%s] is not support now", teeType)
		}

		userData, err := tees.Verifiers[teeType].GetUserData(attestResult)
		if err != nil {
			return fmt.Errorf("get user data faield, error: %s", err)
		}

		if nonce != "" {
			if err := GNonceManager.CheckNonce(nonce); err != nil {
				return err
			}
		}

		logrus.Debugf("user data is %s", userData)
		expectedUserData := fmt.Sprintf("%x", sha256.Sum256([]byte(nonce+runtimeData)))
		logrus.Debugf("expected data is %s", expectedUserData)
		if userData != expectedUserData {
			return fmt.Errorf("userData is not correct")
		}
		return nil
	} else {
		return fmt.Errorf("verify tee result format error")
	}
}

func TrustNodeAppraisal(attestInfo *NodeAttestInfo) (signedToken string, err error) {
	if attestInfo == nil {
		return "", fmt.Errorf("attestInfo is nil")
	}

	verifyTeeResult, err := NodeVerify(attestInfo.Report)
	if err != nil {
		return "", fmt.Errorf("node verify failed, error: %s", err)
	}

	err = UserDataCheck(verifyTeeResult.Tee, attestInfo.Nonce, "")
	if err != nil {
		logrus.Errorf("user data check failed, error:%s", err)
		return "", fmt.Errorf("user data or nonce not correct")
	}

	trustNodeClaims, err := TrustNodePolicyEvaluate(attestInfo.PolicyIds, verifyTeeResult)
	if err != nil {
		return "", fmt.Errorf("policy evaluate failed, error: %s", err)
	}

	claims, err := anyToMap(trustNodeClaims)
	if err != nil {
		return "", fmt.Errorf("convert trust node cliams to map failed, error:%s", err)
	}

	finalToken, err := token.GenerateToken(claims)
	if err != nil {
		errMsg := fmt.Sprintf("generate token failed, error: %s", err)
		logrus.Errorf(errMsg)
		return "", fmt.Errorf(errMsg)
	}

	logrus.Debugf("token is %s", finalToken)

	return finalToken, nil

}

func NodeVerify(report *NodeEvidence) (*TrustNodeVerifiedResult, error) {
	if report == nil {
		return nil, fmt.Errorf("the report in evidence is nil")
	}

	reportData, err := base64.StdEncoding.DecodeString(report.TeeReport)
	if err != nil {
		return nil, fmt.Errorf("base64 decode report failed, error:%s", err)
	}

	if !tees.IsVerifierExists(report.Tee) {
		return nil, fmt.Errorf("tee type [%s] is not support now", report.Tee)
	}

	teeVerifyResult, err := tees.Verifiers[report.Tee].VerifyTeeReport(reportData, report.Parameter)
	if err != nil {
		return nil, fmt.Errorf("verify tee report failed, error: %s", err)
	}
	teeVerifyResult["type"] = report.Tee
	logrus.Debugf("verify result is %v", teeVerifyResult)

	deviceVerifyResults := make([]tees.VerifyTeeResult, 0)
	for _, d := range report.TrustDevice {
		r, err := TrustDeviceVerify(d)
		if err != nil {
			return nil, fmt.Errorf("verify trust device failed, error: %s", err)
		}
		deviceVerifyResults = append(deviceVerifyResults, r)
	}

	return &TrustNodeVerifiedResult{
		Tee:         teeVerifyResult,
		TrustDevice: deviceVerifyResults,
	}, nil
}

func TrustDeviceVerify(t *TrustDeviceReport) (tees.VerifyTeeResult, error) {
	if t == nil {
		return nil, fmt.Errorf("the trust device report is nil")
	}

	reportData, err := base64.StdEncoding.DecodeString(t.DeviceReport)
	if err != nil {
		return nil, fmt.Errorf("base64 decode device report failed, error:%s", err)
	}

	if !tees.IsVerifierExists(t.DeviceType) {
		return nil, fmt.Errorf("tee device [%s] is not support now", t.DeviceType)
	}

	verifyResult, err := tees.Verifiers[t.DeviceType].VerifyTeeReport(reportData, t.Parameter)
	if err != nil {
		return nil, fmt.Errorf("verify tee report failed, error: %s", err)
	}
	verifyResult["type"] = t.DeviceType
	logrus.Debugf("verify result is %v", verifyResult)

	return verifyResult, nil
}

func TrustNodePolicyEvaluate(policyIds []string, trustNode *TrustNodeVerifiedResult) (*TrustNodeClaims, error) {
	var policies []*models.Policy
	if len(policyIds) == 0 {
		policy, err := models.PolicyModel.GetLatestPolicy(models.NodeType)
		if err == nil {
			policies = append(policies, policy)
		}
	} else {
		return nil, fmt.Errorf("not support yet")
	}

	input := struct {
		TrustNode *TrustNodeVerifiedResult `json:"trust_node"`
	}{
		trustNode,
	}

	trustNodeClaims := new(TrustNodeClaims)
	trustNodeClaims.TrustNode = trustNode
	for _, policy := range policies {
		policyString, err := base64.StdEncoding.DecodeString(policy.Rego)
		if err != nil {
			return nil, fmt.Errorf("decode the rego policy of %s failed, error:%s", policy.Id, err)
		}

		logrus.Debugf("policy is %s", policy.Rego)
		pe := policyengine.NewPolicyExecutor("data.trustnode", string(policyString))
		regoResultSet, err := pe.Evaluate(input)
		if err != nil {
			errmsg := fmt.Sprintf("policy evaluate failed, error:%s", err)
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}
		logrus.Debugf("policy evaluate result is %v", regoResultSet[0].Expressions[0].Value)
		regoResult, err := anyToMap(regoResultSet[0].Expressions[0].Value)
		if err != nil {
			errmsg := fmt.Sprintf("rego result format error")
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}

		if regoResult[models.NodeType] == false {
			errmsg := fmt.Sprintf("policy [%s] does not match", policy.Id)
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}

		policyInfo := models.Policy{
			Id:        policy.Id,
			Hash:      policy.Hash,
			Signature: policy.Signature,
		}
		trustNodeClaims.PolicyInfos = append(trustNodeClaims.PolicyInfos, &policyInfo)
	}

	return trustNodeClaims, nil
}

func TrustClusterPolicyEvaluate(policyIds []string, trustNodes []*TrustNodeVerifiedResult) (*TrustClusterClaims, error) {
	var policies []*models.Policy
	if len(policyIds) == 0 {
		policy, err := models.PolicyModel.GetLatestPolicy(models.ClusterType)
		if err == nil {
			policies = append(policies, policy)
		}
	} else {
		return nil, fmt.Errorf("not support yet")
	}

	input := struct {
		TrustCluster []*TrustNodeVerifiedResult `json:"trust_cluster"`
	}{
		trustNodes,
	}

	trustClusterClaims := new(TrustClusterClaims)
	trustClusterClaims.TrustNodes = trustNodes
	for _, policy := range policies {
		policyString, err := base64.StdEncoding.DecodeString(policy.Rego)
		if err != nil {
			return nil, fmt.Errorf("decode the rego policy of %s failed, error:%s", policy.Id, err)
		}

		logrus.Debug("policy is %s", policy.Rego)
		pe := policyengine.NewPolicyExecutor("data.trustcluster", string(policyString))
		regoResultSet, err := pe.Evaluate(input)
		if err != nil {
			errmsg := fmt.Sprintf("policy evaluate failed, error:%s", err)
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}
		logrus.Debugf("policy evaluate result is %v", regoResultSet[0].Expressions[0].Value)
		regoResult, err := anyToMap(regoResultSet[0].Expressions[0].Value)
		if err != nil {
			errmsg := fmt.Sprintf("rego result format error")
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}

		if regoResult[models.NodeType] == false {
			errmsg := fmt.Sprintf("policy [%s] does not match", policy.Id)
			logrus.Errorf(errmsg)
			return nil, fmt.Errorf(errmsg)
		}

		policyInfo := models.Policy{
			Id:        policy.Id,
			Hash:      policy.Hash,
			Signature: policy.Signature,
		}
		trustClusterClaims.PolicyInfos = append(trustClusterClaims.PolicyInfos, &policyInfo)
	}

	return trustClusterClaims, nil
}

func TrustClusterVerify(attestInfo *ClusterAttestInfo) (signedToken string, err error) {
	if attestInfo == nil {
		return "", fmt.Errorf("attestInfo is nil")
	}

	nodeVerifyResults := make([]*TrustNodeVerifiedResult, 0)
	for _, node := range attestInfo.Reports {
		verifyResult, err := NodeVerify(node)
		if err != nil {
			return "", fmt.Errorf("node verify failed, error: %s", err)
		}
		nodeVerifyResults = append(nodeVerifyResults, verifyResult)
	}

	tc, err := TrustClusterPolicyEvaluate(attestInfo.PolicyIds, nodeVerifyResults)
	if err != nil {
		return "", fmt.Errorf("trust cluster policy evaluate failed, error:%s", err)
	}

	claims, err := anyToMap(tc)
	if err != nil {
		return "", fmt.Errorf("convert trust node cliams to map failed, error:%s", err)
	}

	finalToken, err := token.GenerateToken(claims)
	if err != nil {
		errMsg := fmt.Sprintf("generate token failed, error: %s", err)
		logrus.Errorf(errMsg)
		return "", fmt.Errorf(errMsg)
	}

	logrus.Debugf("token is %s", finalToken)

	return finalToken, nil
}

func anyToMap(obj interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(data, &result)
	return result, err
}
