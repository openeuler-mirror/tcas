package controllers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/pkg/errors"
	"net/http"
	"tcas/consts"
	"tcas/models"
)

type UserController struct {
	DefaultController
}

func (c *UserController) Prepare() {
	c.DefaultController.Prepare()
}

func (c *UserController) Create() {
	if models.HasAdminPermission(c.User.Roles) != true {
		message := "no permission"
		errMes := c.HandleErrorStatusUnauthorized(401, message, "")
		logs.Error(errMes)
		return
	}

	var user models.User
	var userid string
	err := json.Unmarshal(c.Ctx.Input.RequestBody, &user)
	if err != nil {
		message := fmt.Sprintf("get body error. %+v", err)
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	if models.IsOrdinaryRole(user.Roles) == false {
		message := fmt.Sprintf("roles error, include not support roles")
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATEUSER_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	if _, err = models.UserModel.GetUserByName("default", user.Name); err == nil {
		message := fmt.Sprintf("create user failed, user is already exist")
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_USER_ALREADY_EXIST, message, "")
		logs.Warning(errMes)
		return
	}

	user.Password = user.InputPassWord
	if userid, err = models.UserModel.AddUser("default", &user); err != nil {
		message := fmt.Sprintf("create user error.%+v", err)
		errMes := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATEUSER_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	addition := fmt.Sprintf("userID is %s", userid)
	mesg, baseRes := c.HandleSuccess(200, "create user successful", addition)
	res := UserIdRes{
		BaseRes: *baseRes,
		UserID:  userid,
	}
	c.Data["json"] = res
	c.ServeJSON()
	logs.Info(mesg)
}

func (c *UserController) DeleteUserById() {
	if models.HasAdminPermission(c.User.Roles) != true {
		message := "no permission"
		errMes := c.HandleErrorStatusUnauthorized(401, message, "")
		logs.Error(errMes)
		return
	}

	id := c.Ctx.Input.Param(":userId")

	if c.DefaultController.User.Id == id {
		message := "no permission, you could not delete your self"
		errMes := c.HandleErrorStatusUnauthorized(consts.ERROR_CODE_DELETE_SELF, message, "")
		logs.Error(errMes)
		return
	}

	du, err := models.UserModel.GetUserById(id)
	if err != nil {
		message := fmt.Sprintf("Get user failed, may user not exist,error: %s", err.Error())
		addition := fmt.Sprintf("user id is %s", id)
		errMes := c.HandleErrorStatusUnauthorized(consts.ERROR_CODE_DELETE_SELF, message, addition)
		logs.Error(errMes)
		return
	}

	if models.HasAdminPermission(du.Roles) == false {
		message := fmt.Sprintf("no permission, %s could not be deleted", du.Roles)
		addition := fmt.Sprintf("user id is %s", id)
		errMes := c.HandleErrorStatusUnauthorized(401, message, addition)
		logs.Error(errMes)
		return
	}

	err = models.UserModel.DeleteUser(id)
	if err != nil {
		c.Data["json"] = &UserIdRes{
			BaseRes: BaseRes{
				Code:    consts.ERROR_CODE_DELETE_USER_FAILED,
				Message: errors.Cause(err).Error(),
			},
			UserID: "",
		}
	} else {
		c.Data["json"] = &UserIdRes{
			BaseRes: BaseRes{
				Code:    200,
				Message: "delete user successful",
			},
			UserID: id,
		}
	}
	c.ServeJSON()
}

func (c *UserController) ResetPassword() {
	var userRep *struct {
		OldPasswd string `json:"oldPasswd"`
		NewPasswd string `json:"newPasswd"`
	}

	err := json.Unmarshal(c.Ctx.Input.RequestBody, &userRep)
	if err != nil {
		message := fmt.Sprintf("user param error; %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	oldPasswd, err := base64.StdEncoding.DecodeString(userRep.OldPasswd)
	if err != nil {
		message := fmt.Sprintf("decode base64 for old passwd failed error: %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, message, "")
		logs.Error(errMes)
		return
	}
	_, err = models.Authenticate(c.User.Name, string(oldPasswd))
	if err != nil {
		logs.Error("try to reset passwd user (%s) error %+v. ", c.User.Name, err)
		c.Ctx.Output.SetStatus(http.StatusUnauthorized)
		c.Data["json"] = BaseRes{
			consts.ERROR_CODE_PASSWD_WRONG,
			fmt.Sprintf("old passwd wrong. %+v", err),
		}
		c.ServeJSON()
		return
	}

	newPasswd, err := base64.StdEncoding.DecodeString(userRep.NewPasswd)
	if err != nil {
		message := fmt.Sprintf("decode base64 for new passwd failed error: %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, message, "")
		logs.Error(errMes)
		return
	}

	err = models.UserModel.ResetUserPassword(c.DefaultController.User.Id, string(newPasswd))
	if err != nil {
		message := fmt.Sprintf("update password error; %s", err.Error())
		errMes := c.DefaultController.HandleErrorStatusBadRequest(consts.ERROR_CODE_UPDATE_PASSWD_FAILED, message, "")
		logs.Error(errMes)
		return
	}

	info, baseRes := c.DefaultController.HandleSuccess(200, "update passwd successful", "")
	logs.Info(info)
	c.Data["json"] = baseRes
	c.ServeJSON()
	return
}

func (c *UserController) QueryUserInfoByCondition() {
	if models.HasAdminPermission(c.User.Roles) != true {
		message := "no permission"
		errMes := c.HandleErrorStatusUnauthorized(401, message, "")
		logs.Error(errMes)
		return
	}
	fc := new(models.UserFilterCondition)
	fc.KeyWord = c.GetString("keyWord")
	p, _ := c.GetInt("page", 0)
	ps, _ := c.GetInt("pageSize", 10)
	fc.Page = int64(p)
	fc.PageSize = int64(ps)
	fc.User = &c.DefaultController.User

	re, err := models.UserModel.GetUserInfoByCondition(fc)
	if err != nil {
		fcInfo, _ := json.Marshal(fc)
		addition := string(fcInfo)
		message := fmt.Sprintf("Get file list failed %s", err.Error())
		mesg := c.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_USERLIST_FAILED, message, addition)
		logs.Error(mesg)
		return
	}

	mesg, baseRes := c.HandleSuccess(200, "get file list successful", "")
	res := PageRes{
		BaseRes:  *baseRes,
		DataPage: re,
	}

	logs.Info(mesg)
	c.Data["json"] = res
	c.ServeJSON()

}

func (c *UserController) CurrentUser() {
	c.User.Password = ""
	mesg, baseRes := c.HandleSuccess(200, "get user info success", "")
	c.Data["json"] = &UserRes{
		*baseRes,
		&c.User,
	}
	logs.Info(mesg)
	c.ServeJSON()
}
