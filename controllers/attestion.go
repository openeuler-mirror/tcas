package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/apprasisal"
	"tcas/consts"
	"tcas/models"
)

type ReportRes struct {
	BaseRes
	ReportData interface{} `json:"reportData"`
}

type TokenRes struct {
	BaseRes
	Token string `json:"token"`
}

type AttestationController struct {
	DefaultController
}

func (uc *AttestationController) AttestTrustNode() {
	var evidence apprasisal.NodeAttestInfo
	if err := json.Unmarshal(uc.Ctx.Input.RequestBody, &evidence); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

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

	_, err := apprasisal.TrustNodeAppraisal(&evidence)
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
