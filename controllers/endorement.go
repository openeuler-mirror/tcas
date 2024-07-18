package controllers

import (
	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/sirupsen/logrus"
	"tcas/endorsement"
)

type EndorsementController struct {
	DefaultController
}

func (uc EndorsementController) GetCa(c *gin.Context) {
	res := struct {
		Keys []jwk.Key `json:"keys"`
	}{
		Keys: []jwk.Key{endorsement.CAJWK},
	}
	c.JSON(200, res)
	logrus.Info("get ca certs successful")
	return
}
