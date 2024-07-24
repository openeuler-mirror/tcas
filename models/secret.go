package models

import (
	"github.com/beego/beego/v2/client/orm"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"time"
)

func init() {
	orm.RegisterModel(new(SecretInfo))
	SecretMd = SecretModle{}
}

var SecretMd SecretModle

type SecretInfo struct {
	Id         string     `orm:"pk;size(255)" json:"id,omitempty"`
	Secret     string     `json:"secret,omitempty"`
	Name       string     `json:"name,omitempty"`
	CreateTime *time.Time `orm:"auto_now_add;type(datetime)" json:"createTime,omitempty"`
	UpdateTime *time.Time `orm:"auto_now;type(datetime)" json:"updateTime,omitempty"`
}

func (u *SecretInfo) TableName() string {
	return TABLE_SECRET
}

type SecretModle struct{}

func (k *SecretModle) InsertSecret(s *SecretInfo) (fileId string, err error) {
	if s == nil {
		return "", errors.New("input is nil")
	}
	s.Id = uuid.New().String()

	o := orm.NewOrm()

	_, err = o.Insert(s)
	if err != nil {
		return "", err
	}
	return s.Id, nil
}

func (k *SecretModle) GetSecretById(id string) (*SecretInfo, error) {
	v := new(SecretInfo)
	if err := orm.NewOrm().QueryTable(TABLE_SECRET).Filter("id", id).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (k *SecretModle) UpdateSecret(s *SecretInfo) (id string, err error) {
	if s == nil {
		return "", errors.New("input is nil")
	}
	o := orm.NewOrm()
	v := SecretInfo{Id: s.Id}
	if err = o.Read(&v, "id"); err != nil {
		return
	}
	v.Name = s.Name
	v.Secret = s.Secret

	_, err = o.Update(&v)
	if err != nil {
		return
	}
	return s.Id, nil
}

func (k *SecretModle) DeleteSecretById(id string) error {
	v := SecretInfo{
		Id: id,
	}
	if err := orm.NewOrm().Read(&v, "id"); err != nil {
		return err
	}
	_, err := orm.NewOrm().Delete(&v)

	if err != nil {
		return err
	}
	return nil
}

func (k *SecretModle) GetSecretList() ([]*SecretInfo, error) {
	v := make([]*SecretInfo, 0)
	if _, err := orm.NewOrm().QueryTable(TABLE_SECRET).All(&v, "Id", "Name", "CreateTime", "UpdateTime"); err != nil {
		return v, err
	}

	return v, nil
}
