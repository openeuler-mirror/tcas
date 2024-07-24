package controllers

import (
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"io"
	"net/http"
	"os"
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
	URI    string
	Method string

	User string
	IP   string

	ResponseStatus int
	RequestBody    string
	RequestAuth    string
}

type KeyInfo struct {
	FileId     string `json:"fileId"`
	Key        string `json:"key"`
	Type       string `json:"type"`
	CreateTime string `json:"createTime"`
	UpdateTime string `json:"updateTime"`
}

type SecretKeyRes struct {
	BaseRes
	Data KeyInfo `json:"data"`
}

type KmsRes struct {
	BaseRes
	FileId string `json:"fileId"`
}

func WriteFile(filename string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	n, err := f.Write(data)
	if err == nil && n < len(data) {
		err = io.ErrShortWrite
	}
	if err1 := f.Close(); err == nil {
		err = err1
	}
	return err
}

func ErrorRes(code int, message string) *BaseRes {
	return &BaseRes{
		Code:    code,
		Message: message,
	}
}

type DefaultController struct {
	beego.Controller
}

func (f *DefaultController) Prepare() {

}

func (f *DefaultController) HandleErrorStatusBadRequest(code int, message string, addition string) (errMesg string) {
	var userName string

	clientIp := f.Ctx.Request.Header.Get("X-Real-ip")
	if clientIp == "" {
		clientIp = f.Ctx.Input.IP()
	}
	requestInfo, err := json.Marshal(RequestMessageData{
		URI:            f.Ctx.Input.URI(),
		Method:         f.Ctx.Request.Method,
		User:           userName,
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
	var userName string

	clientIp := f.Ctx.Request.Header.Get("X-Real-ip")
	if clientIp == "" {
		clientIp = f.Ctx.Input.IP()
	}
	requestInfo, err := json.Marshal(RequestMessageData{
		URI:            f.Ctx.Input.URI(),
		Method:         f.Ctx.Request.Method,
		User:           userName,
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
	var userName string

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
		User:           userName,
		IP:             clientIp,
		ResponseStatus: code,
	})
	if err != nil {
		logs.Error("err:", err.Error())
		return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, err.Error()), baseRes
	}

	return fmt.Sprintf("message: %s; addition: %s; request: %s", message, addition, requestInfo), baseRes
}
