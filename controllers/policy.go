package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/consts"
	"tcas/models"
)

type PolicyController struct {
	DefaultController
}

func (uc PolicyController) CreatePolicy() {
	var policy models.Policy
	if err := json.Unmarshal(uc.Ctx.Input.RequestBody, &policy); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	id, err := models.PolicyModel.AddPolicy(&policy)
	if err != nil {
		message := fmt.Sprintf("create policy failed, error: %s", err.Error())
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "add policy successful", "")

	res := PolicyIdRes{
		*baseRes,
		id,
	}

	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info(mesg)
}

func (uc PolicyController) DeletePolicy() {
	policyId := uc.GetString(":policyId")
	if policyId == "" {
		message := fmt.Sprintf("policy id is null")
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	err := models.PolicyModel.DeletePolicy(policyId)
	if err != nil {
		message := fmt.Sprintf("delete policy failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, fmt.Sprintf("policy id is %s", policyId))
		logs.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "delete report successful", "")

	res := PolicyIdRes{
		*baseRes,
		policyId,
	}

	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info(mesg)
}
