package controllers

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"tcas/apprasisal"
	"tcas/consts"
)

type NonceController struct {
	DefaultController
}

func (uc NonceController) GetNonce(c *gin.Context) {
	nonce, err := apprasisal.GNonceManager.GenerateNonce()
	if err != nil {
		message := fmt.Sprintf("get nonce failed, error: %s", err.Error())
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GENERATE_NONCE_FAILED, message, "", c)
		logrus.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "get nonce successful", "", c)
	res := DataRes{
		BaseRes: *baseRes,
		Data:    nonce,
	}
	c.JSON(200, res)
	logrus.Info(mesg)
	return
}
