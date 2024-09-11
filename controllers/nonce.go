package controllers

import (
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/apprasisal"
	"tcas/consts"
)

type NonceController struct {
	DefaultController
}

func (uc NonceController) Prepare() {

}

func (uc NonceController) GetNonce() {
	nonce, err := apprasisal.GNonceManager.GenerateNonce()
	if err != nil {
		message := fmt.Sprintf("get nonce failed, error: %s", err.Error())
		errMes := uc.HandleErrorStatusBadRequest(consts.ERROR_CODE_GENERATE_NONCE_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	mesg, baseRes := uc.HandleSuccess(200, "get nonce successful", "")
	res := DataRes{
		BaseRes: *baseRes,
		Data:    nonce,
	}
	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info(mesg)
	return
}
