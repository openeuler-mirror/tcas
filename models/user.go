package models

import (
	"encoding/base64"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/google/uuid"
	"strings"
	"tcas/util/encode"
	"tcas/util/encrypt"
	"time"

	"github.com/beego/beego/v2/client/orm"
)

var UserModel *userModel

type UserType int

const (
	Admin      = "admin"
	PolicyUser = "policy"
	SecretUser = "secret"
)

var setVal struct{}
var OrdinaryRoleSet = map[string]struct{}{PolicyUser: setVal, SecretUser: setVal}
var AdminPermissionSet = map[string]struct{}{Admin: setVal}

func init() {
	// init orm tables
	orm.RegisterModel(new(User))
	UserModel = &userModel{}
}

type userModel struct{}

type User struct {
	No            int        `orm:"auto"`
	Id            string     `orm:"unique;size(255)" json:"userId,omitempty"`
	Display       string     `orm:"size(255)" json:"Display,omitempty"`
	Name          string     `orm:"unique;size(200)" json:"userName,omitempty"`
	Department    string     `orm:"size(255)" json:"department,omitempty"`
	InputPassWord string     `orm:"-" json:"password,omitempty"`
	Password      string     `orm:"size(255)" json:"-"`
	Salt          string     `orm:"size(32)" json:"-"`
	Email         string     `orm:"size(200)" json:"email,omitempty"`
	Status        string     `orm:"size(200)" json:"status,omitempty"`
	Comment       string     `orm:"type(text)" json:"comment,omitempty"`
	Roles         string     `orm:"size(32)" json:"roles,omitempty"`
	ApiKey        string     `orm:"size(255);unique" json:"apiKey"`
	LastLogin     *time.Time `orm:"auto_now_add;type(datetime)" json:"lastLogin,omitempty"`
	LastIp        string     `orm:"size(200)" json:"lastIp,omitempty"`
	CreateTime    *time.Time `orm:"auto_now_add;type(datetime)" json:"createTime,omitempty"`
	UpdateTime    *time.Time `orm:"auto_now;type(datetime)" json:"updateTime,omitempty"`
}

type UserStatistics struct {
	Total int64 `json:"total,omitempty"`
}

type UserFilterCondition struct {
	Page     int64
	PageSize int64
	KeyWord  string
	User     *User
}

func (u *User) TableName() string {
	return TABLE_USER
}

func (u *userModel) AddUser(dbname string, m *User) (id string, err error) {
	o := orm.NewOrmUsingDB(dbname)
	if o == nil {
		return "", fmt.Errorf("o is nil")
	}
	m.Id = "user-" + uuid.New().String()
	m.ApiKey, err = encrypt.GenerateKey()
	if err != nil {
		return "", err
	}
	passwd, err := base64.StdEncoding.DecodeString(m.Password)
	if err != nil {
		logs.Error("decode base64 for password failed error: %s", err)
		return "", err
	}
	salt := encode.GetRandomString(10)
	passwordHashed := encode.EncodePassword(string(passwd), salt)
	m.Salt = salt
	m.Password = passwordHashed
	m.Status = "first"
	_, err = o.Insert(m)
	if err != nil {
		return "", err
	}
	return m.Id, nil
}

func (*userModel) GetNames() ([]User, error) {
	users := []User{}
	_, err := orm.NewOrm().
		QueryTable(new(User)).
		All(&users, "ID", "Name")

	if err != nil {
		return nil, err
	}

	return users, nil
}

func (*userModel) GetUserById(id string) (v *User, err error) {
	v = new(User)
	if err = orm.NewOrmUsingDB("default").QueryTable(TABLE_USER).Filter("id", id).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (*userModel) GetUserByName(dbname string, name string) (v *User, err error) {
	v = &User{Name: name}
	if err = orm.NewOrmUsingDB(dbname).Read(v, "Name"); err != nil {
		return nil, err
	}
	return v, nil
}

func (*userModel) GetUserByApiKey(apiKey string) (v *User, err error) {
	v = new(User)
	if err = orm.NewOrmUsingDB("default").QueryTable(TABLE_USER).Filter("apiKey", apiKey).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (*userModel) EnsureUser(m *User) (*User, error) {
	oldUser := &User{Name: m.Name}
	err := orm.NewOrm().Read(oldUser, "Name")
	if err != nil {
		if err == orm.ErrNoRows {
			_, err := UserModel.AddUser("default", m)
			if err != nil {
				return nil, err
			}
			oldUser = m
		} else {
			return nil, err
		}
	} else {
		oldUser.Email = m.Email
		oldUser.LastLogin = m.LastLogin
		oldUser.LastIp = m.LastIp
		_, err := orm.NewOrm().Update(oldUser)
		if err != nil {
			return nil, err
		}
	}

	return oldUser, err
}

func (*userModel) ResetUserPassword(id string, password string) (err error) {
	v := &User{Id: id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return
	}
	salt := encode.GetRandomString(10)
	passwordHashed := encode.EncodePassword(password, salt)

	v.Password = passwordHashed
	v.Salt = salt
	v.Status = ""
	_, err = orm.NewOrm().Update(v)
	return
}

func (*userModel) UpdateUserById(m *User) (err error) {
	v := &User{Id: m.Id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return
	}
	v.Name = m.Name
	v.Email = m.Email
	v.Comment = m.Comment
	v.Status = m.Status
	v.Display = m.Display
	v.Department = m.Department
	_, err = orm.NewOrm().Update(v)
	return
}

func (*userModel) UpdateApiKeyById(id string) (key string, err error) {
	v := &User{Id: id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return "", err
	}

	v.ApiKey, err = encrypt.GenerateKey()
	if err != nil {
		return "", err
	}
	_, err = orm.NewOrm().Update(v)
	return v.ApiKey, nil
}

func (*userModel) DeleteUser(id string) (err error) {
	v := &User{Id: id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return
	}
	_, err = orm.NewOrm().Delete(&User{No: v.No})
	return
}

func (*userModel) GetUserInfoByCondition(fc *UserFilterCondition) (*DataPage, error) {
	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_USER)

	var userInfos []*User
	cond := orm.NewCondition()

	logs.Debug("Get user Info list condition : %+v", fc)
	if fc.KeyWord != "" {
		kw := fc.KeyWord
		condKeyWord := orm.NewCondition().And("Name__icontains", kw).Or("Department__icontains", kw).Or("Display__icontains", kw)
		cond = cond.AndCond(condKeyWord)
	}
	qs = qs.SetCond(cond)
	qs = qs.Exclude("status", "delete") //filter the deleted data
	total, err := qs.Count()
	if err != nil {
		logs.Error("get user Info list total count error:", err.Error())
		return nil, err
	}
	logs.Debug("get user Info list total count :%d", total)
	totalPage, offset, limit := GetPageInfo(total, fc.Page, fc.PageSize)

	qs = qs.Limit(limit, offset)
	currentCnt, err := qs.OrderBy("-updateTime", "-createTime").All(&userInfos)
	if err != nil {
		logs.Error("Get user Info list from db,error:%s", err.Error())
		return nil, err
	}

	for i := 0; i < len(userInfos); i++ {
		userInfos[i].Password = ""
	}

	logs.Info("Get user Info list from db success,currentCnt is %d", currentCnt)
	re := new(DataPage)
	re.TotalData = total
	re.TotalPage = totalPage
	re.Page = fc.Page
	re.PageSize = limit
	re.CurrentCnt = currentCnt
	re.DataList = userInfos
	return re, nil
}

func (u *userModel) ResetUser(m *User) (id string, err error) {
	o := orm.NewOrm()
	salt := encode.GetRandomString(10)
	passwordHashed := encode.EncodePassword("tcas@123456", salt)
	m.Salt = salt
	m.Password = passwordHashed
	m.Status = "first"
	_, err = o.Update(m)
	if err != nil {
		return "", err
	}
	return m.Id, nil
}

func (*userModel) GetAllUserInfoByCondition() ([]*User, error) {
	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_USER)
	var userInfos []*User
	_, err := qs.OrderBy("-updateTime", "-createTime").All(&userInfos)
	if err != nil {
		logs.Error("Get user Info list from db,error:%s", err.Error())
		return nil, err
	}
	return userInfos, nil
}

func Authenticate(username, password string) (*User, error) {
	user, err := UserModel.GetUserByName("default", username)
	if err != nil {
		if err == orm.ErrNoRows {
			return nil, fmt.Errorf("username or password error")
		}
		return nil, err
	}

	passwordHashed := encode.EncodePassword(password, user.Salt)

	if passwordHashed != user.Password {
		return nil, fmt.Errorf("username or password error")
	}
	return user, nil
}

func HasAdminPermission(roles string) bool {
	roleList := strings.Split(roles, ",")
	for _, r := range roleList {
		if _, ok := AdminPermissionSet[r]; ok {
			return true
		}
	}
	return false
}

func HasPolicyPermission(roles string) bool {
	roleList := strings.Split(roles, ",")
	for _, r := range roleList {
		if r == PolicyUser {
			return true
		}
	}
	return false
}

func HasSecretPermission(roles string) bool {
	roleList := strings.Split(roles, ",")
	for _, r := range roleList {
		if r == SecretUser {
			return true
		}
	}
	return false
}

func IsOrdinaryRole(roles string) bool {
	roleList := strings.Split(roles, ",")
	for _, r := range roleList {
		if _, ok := OrdinaryRoleSet[r]; !ok {
			return false
		}
	}
	return true
}
