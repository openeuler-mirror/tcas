package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"tcas/consts"
	"tcas/models"
)

type PolicyController struct {
	DefaultController
}

func (uc PolicyController) CreatePolicy(c *gin.Context) {
	var policy models.Policy
	if err := c.BindJSON(&policy); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}

	id, err := models.PolicyModel.AddPolicy(&policy)
	if err != nil {
		message := fmt.Sprintf("create policy failed, error: %s", err.Error())
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "get report successful", "", c)

	res := PolicyIdRes{
		*baseRes,
		id,
	}

	c.JSON(200, res)
	logrus.Info(mesg)
}

func (uc PolicyController) DeletePolicy(c *gin.Context) {
	policyId := c.Param("policyId")
	if policyId == "" {
		message := fmt.Sprintf("policy id is null")
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}

	err := models.PolicyModel.DeletePolicy(policyId)
	if err != nil {
		message := fmt.Sprintf("delete policy failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, fmt.Sprintf("policy id is %s", policyId), c)
		logrus.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "delete report successful", "", c)

	res := PolicyIdRes{
		*baseRes,
		policyId,
	}

	c.JSON(200, res)
	logrus.Info(mesg)
}
