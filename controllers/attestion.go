package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
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

func (uc AttestationController) AttestTrustNode(c *gin.Context) {
	var evidence apprasisal.NodeAttestInfo
	if err := c.BindJSON(&evidence); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}
	fmt.Println(evidence.Report.Parameter)
	re, err := apprasisal.TrustNodeAppraisal(&evidence)
	if err != nil {
		message := fmt.Sprintf("node attest failed, error: %s", err)
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_ATTEST_TRUSTNODE_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}
	mesg, baseRes := uc.HandleSuccess(200, "attest successful", "", c)

	res := TokenRes{
		*baseRes,
		re,
	}

	c.JSON(200, res)
	logrus.Info(mesg)
}
