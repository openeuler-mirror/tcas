package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/apprasisal"
	"tcas/consts"
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
	fmt.Println(evidence.Report.Parameter)
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
