package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
	"net/http"
	"tcas/consts"
	"tcas/initial"
	"tcas/models"
)

type BaseRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type DataRes struct {
	BaseRes
	Data interface{} `json:"data,omitempty"`
}

type IdRes struct {
	BaseRes
	Id string `json:"id,omitempty"`
}

type PolicyIdRes struct {
	BaseRes
	PolicyId string `json:"policy_id,omitempty"`
}

type RequestMessageData struct {
	URI            string
	Method         string
	User           string
	IP             string
	ResponseStatus int
	RequestBody    string
	RequestAuth    string
}

func ErrorRes(code int, message string) *BaseRes {
	return &BaseRes{
		Code:    code,
		Message: message,
	}
}

type DefaultController struct {
	beego.Controller
	User models.User
}

type PageRes struct {
	BaseRes
	DataPage *models.DataPage `json:"dataPage,omitempty"`
}

type UserIdRes struct {
	BaseRes
	UserID string `json:"userID"`
}

type UserRes struct {
	BaseRes
	User *models.User
}

func (f *DefaultController) Prepare() {
	authString := f.Ctx.Input.Header("Authorization")
	token, err := jwt.Parse(authString, func(token *jwt.Token) (interface{}, error) {
		// since we only use the one private key to sign the tokens,
		// we also only use its public counterpart to verify
		return initial.RsaPublicKey, nil
	})
	errResult := BaseRes{}
	switch err.(type) {
	case nil: // no error
		if !token.Valid { // but may still be invalid
			errResult.Code = consts.ERROR_CODE_LOGIN_EXPIRED
			errResult.Message = "Token Invalid ! "
		}

	case *jwt.ValidationError:
		errResult.Code = consts.ERROR_CODE_LOGIN_EXPIRED
		errResult.Message = err.Error()

	default: // something else went wrong
		errResult.Code = consts.ERROR_CODE_LOGIN_EXPIRED
		errResult.Message = err.Error()
	}

	if err != nil {
		errMes := f.HandleErrorStatusUnauthorized(errResult.Code, errResult.Message, "")
		logs.Error(errMes)
		return
	}
	claim := token.Claims.(jwt.MapClaims)
	id, ok := claim["userId"].(string)
	if !ok {
		errMes := f.HandleErrorStatusUnauthorized(consts.ERROR_CODE_LOGIN_EXPIRED, "illegal token", "")
		logs.Error(errMes)
		return
	}
	User, err := models.UserModel.GetUserById(id)
	if err != nil {
		errMes := f.HandleErrorStatusUnauthorized(consts.ERROR_CODE_LOGIN_EXPIRED, "illegal user", "")
		logs.Error(errMes)
		return
	}
	f.User = *User
	f.User.Password = ""

	logs.Debug("user %s try to request %s", f.User.Name, f.Ctx.Input.URL())
}

func (f *DefaultController) HandleErrorStatusBadRequest(code int, message string, addition string) (errMesg string) {

	clientIp := f.Ctx.Request.Header.Get("X-Real-ip")
	if clientIp == "" {
		clientIp = f.Ctx.Input.IP()
	}
	requestInfo, err := json.Marshal(RequestMessageData{
		URI:            f.Ctx.Input.URI(),
		Method:         f.Ctx.Request.Method,
		User:           f.User.Name,
		IP:             clientIp,
		ResponseStatus: code,
	})
	if err != nil {
		logs.Error("err:", err.Error())
		return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, err.Error())
	}

	f.Ctx.Output.SetStatus(http.StatusBadRequest)
	f.Data["json"] = ErrorRes(code, message)
	f.ServeJSON()

	return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, requestInfo)
}

func (f *DefaultController) HandleErrorStatusUnauthorized(code int, message string, addition string) (errMesg string) {
	clientIp := f.Ctx.Request.Header.Get("X-Real-ip")
	if clientIp == "" {
		clientIp = f.Ctx.Input.IP()
	}
	requestInfo, err := json.Marshal(RequestMessageData{
		URI:            f.Ctx.Input.URI(),
		Method:         f.Ctx.Request.Method,
		User:           f.User.Name,
		IP:             clientIp,
		ResponseStatus: code,
	})
	if err != nil {
		logs.Error("err:", err.Error())
		return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, err.Error())
	}

	f.Ctx.Output.SetStatus(http.StatusUnauthorized)
	f.Data["json"] = ErrorRes(code, message)
	f.ServeJSON()
	return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, requestInfo)
}

func (f *DefaultController) HandleSuccess(code int, message string, addition string) (info string, baseRes *BaseRes) {
	baseRes = &BaseRes{
		code,
		message,
	}

	clientIp := f.Ctx.Request.Header.Get("X-Real-ip")
	if clientIp == "" {
		clientIp = f.Ctx.Input.IP()
	}
	requestInfo, err := json.Marshal(RequestMessageData{
		URI:            f.Ctx.Input.URI(),
		Method:         f.Ctx.Request.Method,
		User:           f.User.Name,
		IP:             clientIp,
		ResponseStatus: code,
	})
	if err != nil {
		logs.Error("err:", err.Error())
		return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, err.Error()), baseRes
	}

	return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, requestInfo), baseRes
}
