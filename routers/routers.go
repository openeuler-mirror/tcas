package routers

import (
	beego "github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/filter/cors"
	"tcas/controllers"
)

func init() {
	beego.InsertFilter("*", beego.BeforeRouter, cors.Allow(&cors.Options{
		AllowAllOrigins:  true,
		AllowMethods:     []string{"*"},
		AllowHeaders:     []string{"*", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	ns_attest := beego.NewNamespace("/v1/attest",
		beego.NSRouter("", &controllers.AttestationController{}, "post:AttestTrustNode"),
		beego.NSRouter("/getsecret", &controllers.AttestationController{}, "post:GetSecretById"),
	)
	beego.AddNamespace(ns_attest)

	ns_policy := beego.NewNamespace("/v1/policy",
		beego.NSRouter("", &controllers.PolicyController{}, "post:CreatePolicy"),
		beego.NSRouter("/:policyId", &controllers.PolicyController{}, "delete:DeletePolicy"),
	)
	beego.AddNamespace(ns_policy)

	ns_pki := beego.NewNamespace("/v1/pki",
		beego.NSRouter("/ca", &controllers.EndorsementController{}, "get:GetCa"),
	)
	beego.AddNamespace(ns_pki)

	ns_nonce := beego.NewNamespace("/v1/nonce",
		beego.NSRouter("", &controllers.NonceController{}, "get:GetNonce"),
	)
	beego.AddNamespace(ns_nonce)

	ns_secret := beego.NewNamespace("/v1/secret",
		beego.NSRouter("", &controllers.SecretController{}, "post:AddSecret"),
		beego.NSRouter("/:secretId", &controllers.SecretController{}, "delete:DeleteSecret"),
		beego.NSRouter("", &controllers.SecretController{}, "put:UpdateSecret"),
		beego.NSRouter("/list", &controllers.SecretController{}, "get:GetSecretBriefList"),
	)
	beego.AddNamespace(ns_secret)
}
