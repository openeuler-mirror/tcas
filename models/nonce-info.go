package models

import (
	"time"

	"github.com/beego/beego/v2/client/orm"
)

var NonceModel *nonceModel

func init() {
	// init orm tables
	orm.RegisterModel(new(Nonce))
	NonceModel = &nonceModel{}
}

type nonceModel struct{}

type Nonce struct {
	Id          string    `orm:"unique;size(255)" json:"nonce,omitempty"`
	ExpiredTime time.Time `orm:"type(datetime)" json:"expired,omitempty"`
	CreateTime  time.Time `orm:"auto_now_add;type(datetime)" json:"-"`
}

func (u *Nonce) TableName() string {
	return TABLE_NONCE
}

func (m *nonceModel) AddNonce(p *Nonce) (id string, err error) {
	o := orm.NewOrm()

	_, err = o.Insert(p)
	if err != nil {
		return "", err
	}
	return p.Id, nil
}

func (m *nonceModel) GetNonceById(id string) (v *Nonce, err error) {
	v = new(Nonce)
	if err = orm.NewOrmUsingDB("default").QueryTable(TABLE_NONCE).Filter("id", id).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (m *nonceModel) DeleteNonce(id string) (err error) {
	v := &Nonce{Id: id}
	_, err = orm.NewOrm().Delete(v)
	return nil
}
