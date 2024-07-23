package routers

import (
	"github.com/gin-gonic/gin"
	"tcas/controllers"
)

func InitRouters() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	attest := router.Group("/v1/attest")

	attestationController := controllers.AttestationController{}
	//attest.POST("/report", attestationController.GetReport)
	attest.POST("", attestationController.AttestTrustNode)

	policy := router.Group("/v1/policy")
	policyController := controllers.PolicyController{}
	policy.POST("", policyController.CreatePolicy)
	policy.DELETE("/:policyId", policyController.DeletePolicy)

	pki := router.Group("/v1/pki")
	endorsementController := controllers.EndorsementController{}
	pki.GET("/ca", endorsementController.GetCa)

	nonce := router.Group("/v1/nonce")
	nonceController := controllers.NonceController{}
	nonce.GET("", nonceController.GetNonce)

	return router
}
