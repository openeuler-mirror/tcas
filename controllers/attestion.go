package controllers

import (
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/apprasisal"
	"tcas/consts"
	"tcas/models"
	"tcas/pki"
)

type ReportRes struct {
	BaseRes
	ReportData interface{} `json:"reportData"`
}

type TokenRes struct {
	BaseRes
	Token string `json:"token"`
}

type TrustNodeCertReq struct {
	AttestInfo apprasisal.NodeAttestInfo `json:"attestInfo"`
	CSR        *pki.X509Info             `json:"csr"`
}

type AttestationController struct {
	DefaultController
	Policies []*models.Policy
}

func (uc *AttestationController) Prepare() {
	apikey := uc.Ctx.Input.Header("API-KEY")
	if apikey != "" {
		user, err := models.UserModel.GetUserByApiKey(apikey)
		if err != nil {
			message := fmt.Sprintf("no permission")
			errMes := uc.HandleErrorStatusUnauthorized(401, message, "")
			logs.Error(errMes)
			return
		}
		uc.User = *user
	}
}

func (uc *AttestationController) AttestTrustNode() {
	var evidence apprasisal.NodeAttestInfo
	if err := json.Unmarshal(uc.Ctx.Input.RequestBody, &evidence); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	policies, err := uc.getPolicies(evidence.PolicyIds)
	if err != nil {
		message := fmt.Sprintf("get policy failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "")
		logs.Error(errMes)
	}
	evidence.Policies = policies

	re, err := apprasisal.TrustNodeAppraisal(&evidence)
	if err != nil {
		message := fmt.Sprintf("node attest failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "")
		logs.Error(errMes)
		return
	}
	mesg, baseRes := uc.HandleSuccess(200, "attest successful", "")

	res := TokenRes{
		*baseRes,
		re,
	}

	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info(mesg)
}

func (uc *AttestationController) GetSecretById() {
	secretId := uc.Ctx.Request.Header.Get("SecretId")
	if secretId == "" {
		message := fmt.Sprintf("SecretId is null, must add SecretId in header")
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_SECRET_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	var evidence apprasisal.NodeAttestInfo
	if err := json.Unmarshal(uc.Ctx.Input.RequestBody, &evidence); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	if evidence.Nonce == "" {
		message := fmt.Sprintf("nonce in null, doing get secret must provider nonce")
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_SECRET_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	policies, err := uc.getPolicies(evidence.PolicyIds)
	if err != nil {
		message := fmt.Sprintf("get policy failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "")
		logs.Error(errMes)
	}
	evidence.Policies = policies

	_, err = apprasisal.TrustNodeAppraisal(&evidence)
	if err != nil {
		message := fmt.Sprintf("node attest failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	secretInfo, err := models.SecretMd.GetSecretById(secretId)
	if err != nil {
		message := fmt.Sprintf("get secret info failed, secret id : %s, error:%s", secretId, err.Error())
		errMsg := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_SECRET_ERROR, message, "")
		logs.Error(errMsg)
		return
	}

	secretMap, err := ParseSecretToMap(secretInfo.Secret)
	if err != nil {
		message := fmt.Sprintf("get secret info failed, secret id : %s, error:%s", secretId, err.Error())
		errMsg := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_SECRET_ERROR, message, "")
		logs.Error(errMsg)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "get secret info successful", "")
	logs.Info(mesg)
	res := SecretRes{
		*baseRes,
		secretMap,
	}
	uc.Data["json"] = res
	uc.ServeJSON()
	return
}

func (uc *AttestationController) AttestForGetCert() {
	var req TrustNodeCertReq
	if err := json.Unmarshal(uc.Ctx.Input.RequestBody, &req); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	pubKey, err := decodePublicKeyFromRuntimeData(req.AttestInfo.Report.RuntimeData)
	if err != nil {
		message := fmt.Sprintf("decode PublicKey From RuntimeData failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_CERT_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	if req.AttestInfo.Nonce == "" {
		message := fmt.Sprintf("nonce in null, doing get cert must provider nonce")
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_SECRET_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	policies, err := uc.getPolicies(req.AttestInfo.PolicyIds)
	if err != nil {
		message := fmt.Sprintf("get policy failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "")
		logs.Error(errMes)
	}
	req.AttestInfo.Policies = policies

	token, err := apprasisal.TrustNodeAppraisal(&req.AttestInfo)
	if err != nil {
		message := fmt.Sprintf("node attest failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_CERT_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	cert, err := pki.CertManager.GenerateServerCerts(req.CSR, pubKey, token)
	if err != nil {
		message := fmt.Sprintf("node attest failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_CERT_ERROR, message, "")
		logs.Error(errMes)
		return
	}
	mesg, baseRes := uc.HandleSuccess(200, "attest successful", "")

	data := struct {
		X5C          []string `json:"x5c"`
		SerialNumber string   `json:"serial_number"`
	}{
		[]string{base64.StdEncoding.EncodeToString(cert.Raw)},
		fmt.Sprintf("%s", cert.SerialNumber),
	}

	fmt.Printf("%v", data)
	res := DataRes{
		*baseRes,
		data,
	}

	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info(mesg)
}

func (uc *AttestationController) getPolicies(PolicyIds []string) ([]*models.Policy, error) {
	policies := make([]*models.Policy, 0)
	if uc.User.Id != "" {
		// if not assign policy ids, use the latest policy
		if len(PolicyIds) == 0 {
			latestPolicy, err := models.PolicyModel.GetLatestPolicy(models.NodeType, uc.User.Id)
			if err == nil {
				policies = append(policies, latestPolicy)
			}
		} else {
			for _, pid := range PolicyIds {
				policy, err := models.PolicyModel.GetPolicyById(pid)
				if err != nil || policy.UserId != uc.User.Id {
					return nil, fmt.Errorf("unknow policy id: %s", pid)
				}
				policies = append(policies, policy)
			}
		}
	}
	return policies, nil
}

func decodePublicKeyFromRuntimeData(base64Pubkey string) (*ecdsa.PublicKey, error) {
	pemData, err := base64.StdEncoding.DecodeString(base64Pubkey)
	if err != nil {
		message := fmt.Sprintf("base64 decode the pubkey failed, error: %s", err)
		return nil, fmt.Errorf(message)
	}

	ECPrivateKey, err := pki.ParsePublicKeyFromPem(pemData)
	if err != nil {
		message := fmt.Sprintf("parse publick key failed, error: %s", err)
		return nil, fmt.Errorf(message)
	}
	return ECPrivateKey, nil

}
