package controllers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"tcas/consts"
	"tcas/models"
)

type SecretController struct {
	DefaultController
}

type SecretInfoRes struct {
	BaseRes
	models.SecretInfo
}

type SecretRes struct {
	BaseRes
	Secret interface{} `json:"secret"`
}

func (c *SecretController) Prepare() {
	c.DefaultController.Prepare()
	if !models.HasSecretPermission(c.User.Roles) {
		message := fmt.Sprintf("no permission to manager secret")
		errMes := c.HandleErrorStatusBadRequest(401, message, "")
		logs.Error(errMes)
		return
	}
}

func (c *SecretController) AddSecret() {
	var secret models.SecretInfo
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &secret); err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	_, err := ParseSecretToMap(secret.Secret)
	if err != nil {
		message := fmt.Sprintf("failed to parse secret, error: %s", err)
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	secret.UserId = c.User.Id
	id, err := models.SecretMd.InsertSecret(&secret)
	if err != nil {
		message := fmt.Sprintf("create secret failed, error: %s", err.Error())
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	mesg, baseRes := c.HandleSuccess(200, "add secret successful", "")

	res := IdRes{
		*baseRes,
		id,
	}

	c.Data["json"] = res
	c.ServeJSON()
	logs.Info(mesg)
}

func (c *SecretController) UpdateSecret() {
	secretInfo := new(models.SecretInfo)
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &secretInfo)
	if err != nil {
		message := fmt.Sprintf("user param error; %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	_, err = ParseSecretToMap(secretInfo.Secret)
	if err != nil {
		message := fmt.Sprintf("failed to parse secret, error: %s", err)
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_UPDATESECRET_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	secretInfo.UserId = c.User.Id
	id, err := models.SecretMd.UpdateSecret(secretInfo)
	if err != nil {
		message := fmt.Sprintf("update secret failed, error %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE_UPDATESECRET_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	addition := fmt.Sprintf("secret Id is %s", id)
	mesg, baseRes := c.HandleSuccess(200, "update secret successful", addition)
	logs.Info(mesg)
	res := IdRes{
		*baseRes,
		id,
	}
	c.Data["json"] = res
	c.ServeJSON()
	return

}

func (c *SecretController) DeleteSecret() {
	id := c.Ctx.Input.Param(":secretId")
	if id == "" {
		message := "id is null"
		errMsg := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_DELETESECRET_ERROR, message, "")
		logs.Error(errMsg)
		return
	}

	secret, err := models.SecretMd.GetSecretById(id)
	if err != nil {
		message := fmt.Sprintf("get secret info failed, secret id : %s, error:%s", id, err.Error())
		errMsg := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_DELETESECRET_ERROR, message, "")
		logs.Error(errMsg)
		return
	}

	if secret.UserId != c.User.Id {
		message := fmt.Sprintf("secret  doesn't exist")
		errMsg := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_DELETESECRET_ERROR, message, "")
		logs.Error(errMsg)
		return
	}

	err = models.SecretMd.DeleteSecretById(id)
	addition := fmt.Sprintf("secret id is %s", id)

	mesg, baseRes := c.HandleSuccess(200, "delete secret info successful", addition)
	logs.Info(mesg)
	c.Data["json"] = baseRes
	c.ServeJSON()
	return
}

func (c *SecretController) GetSecretBriefList() {
	list, err := models.SecretMd.GetSecretList(c.User.Id)
	if err != nil {
		logs.Error("get secret list failed, error: %s", err)
	}
	mesg, baseRes := c.HandleSuccess(200, "get secret list successful", "")
	logs.Info(mesg)

	res := DataRes{
		*baseRes,
		list,
	}
	c.Data["json"] = res
	c.ServeJSON()
	return
}

func ParseSecretToMap(secret string) (map[string]interface{}, error) {
	secretByte, err := base64.StdEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed,error: %s", err)
	}

	var secretMap map[string]interface{}
	err = json.Unmarshal(secretByte, &secretMap)
	if err != nil {
		return nil, fmt.Errorf("secret is not json")
	}
	return secretMap, nil
}
