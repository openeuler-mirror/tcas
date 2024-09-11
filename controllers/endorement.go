package controllers

import (
	"github.com/beego/beego/v2/core/logs"
	"github.com/lestrrat-go/jwx/jwk"
	"tcas/endorsement"
)

type EndorsementController struct {
	DefaultController
}

func (uc EndorsementController) Prepare() {

}

func (uc EndorsementController) GetCa() {
	res := struct {
		Keys []jwk.Key `json:"keys"`
	}{
		Keys: []jwk.Key{endorsement.CAJWK},
	}
	uc.Data["json"] = res
	uc.ServeJSON()
	logs.Info("get ca certs successful")
	return
}
