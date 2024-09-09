package controllers

import (
	"encoding/base64"
	"encoding/json"
	"github.com/beego/beego/v2/core/logs"
	"github.com/google/uuid"
	"tcas/consts"
	"tcas/initial"
	"tcas/models"
	"time"

	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
)

const (
	issuer = "tcas"
)

// AuthController operations for Auth
type AuthController struct {
	DefaultController
}

// login post data
type LoginData struct {
	UserName string `json:"userName"`
	Password string `json:"passWord"`
}

type LoginResult struct {
	Token  string `json:"token"`
	UserID string `json:"userID"`
}

type LoginRes struct {
	BaseRes
	LoginResult
}

func (c *AuthController) Prepare() {

}

func (c *AuthController) Login() {
	var postData LoginData
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &postData)
	if err != nil {
		errMsg := c.HandleErrorStatusBadRequest(400, "login failed, "+err.Error(), "")
		logs.Error(errMsg)
		return
	}

	userName, err := base64.StdEncoding.DecodeString(postData.UserName)
	if err != nil {
		logs.Error("decode base64 for userName failed error: %s", err)
		c.HandleErrorStatusBadRequest(400, "login failed, "+err.Error(), "")
		return
	}

	passwd, err := base64.StdEncoding.DecodeString(postData.Password)
	if err != nil {
		logs.Error("decode base64 for password failed error: %s", err)
		c.HandleErrorStatusBadRequest(400, "login failed, "+err.Error(), "")
		return
	}

	user, err := models.Authenticate(string(userName), string(passwd))
	if err != nil {
		logs.Warning("try to login in with user (%s) error %+v. ", userName, err)
		c.HandleErrorStatusUnauthorized(401, "login failed, "+err.Error(), "")
		return
	}

	now := time.Now()
	// default token exp time is 15min.
	expSecond := beego.AppConfig.DefaultInt64("LoginTokenLifeTime", 15)
	//add the limit of token exp time 60min
	if expSecond > 60 {
		expSecond = 60
	}
	claims := jwt.MapClaims{
		"iat":    now.Unix(),
		"exp":    now.Add(time.Duration(expSecond) * time.Minute).Unix(),
		"nbf":    now.Unix() - 1000,
		"iss":    issuer,
		"jti":    uuid.NewString(),
		"userId": user.Id,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	apiToken, err := token.SignedString(initial.RsaPrivateKey)
	if err != nil {
		logs.Error("create token  error:", err.Error())
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_LOGIN_FAILED, "login failed. "+err.Error(), "")
		return
	}

	loginResult := LoginResult{
		Token:  apiToken,
		UserID: user.Id,
	}

	_, baseRes := c.HandleSuccess(200, "login success", "")
	c.Data["json"] = LoginRes{
		*baseRes,
		loginResult,
	}
	c.ServeJSON()
	logs.Info("login success from %s,userName:%s", user.LastIp, user.Name)
}
