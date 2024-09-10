package models

import (
	"crypto/sha256"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/google/uuid"
	"time"

	"github.com/beego/beego/v2/client/orm"
)

const NodeType = "trust_node"
const ClusterType = "trust_cluster"

var PolicyModel *policyModel

func init() {
	// init orm tables
	orm.RegisterModel(new(Policy))
	PolicyModel = &policyModel{}
}

type policyModel struct{}

type Policy struct {
	No              int        `orm:"auto" json:"no,omitempty"`
	Id              string     `orm:"unique;size(255)" json:"policy_id,omitempty"`
	Rego            string     `orm:"size(2048)" json:"policy_rego,omitempty"`
	Name            string     `orm:"size(200)" json:"policy_name,omitempty"`
	AttestationType string     `orm:"size(2048)" json:"attestation_type,omitempty"`
	Hash            string     `orm:"size(255)" json:"policy_hash,omitempty"`
	Signature       string     `orm:"size(255)" json:"policy_signature,omitempty"`
	Version         int        `orm:"size(255)" json:"version,omitempty"`
	UserId          string     `orm:"size(255)" json:"userId,omitempty"`
	CreateTime      *time.Time `orm:"auto_now_add;type(datetime)" json:"createTime,omitempty"`
	UpdateTime      *time.Time `orm:"auto_now;type(datetime)" json:"updateTime,omitempty"`
}

type PolicyFilterCondition struct {
	Page     int64
	PageSize int64
	KeyWord  string
	Policy   *Policy
}

func (u *Policy) TableName() string {
	return TABLE_POLICY
}

func (m *policyModel) AddPolicy(p *Policy) (id string, err error) {
	o := orm.NewOrm()
	p.Id = uuid.New().String()
	p.Version = 1
	p.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(p.Rego)))
	if p.AttestationType == "" {
		p.AttestationType = NodeType
	}
	_, err = o.Insert(p)
	if err != nil {
		return "", err
	}
	return p.Id, nil
}

func (m *policyModel) GetPolicyById(id string) (v *Policy, err error) {
	v = new(Policy)
	if err = orm.NewOrmUsingDB("default").QueryTable(TABLE_POLICY).Filter("id", id).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (m *policyModel) UpdatePolicyById(mp *Policy) (err error) {
	v := &Policy{Id: mp.Id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return
	}
	v.Rego = mp.Rego
	v.Signature = mp.Signature
	v.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(mp.Rego)))
	v.Version = v.Version + 1
	_, err = orm.NewOrm().Update(v)
	return
}

func (m *policyModel) DeletePolicy(id string) (err error) {
	v := &Policy{Id: id}
	if err = orm.NewOrm().Read(v, "id"); err != nil {
		return err
	}
	_, err = orm.NewOrm().Delete(&Policy{No: v.No})
	return nil
}

func (m *policyModel) GetPolicies(attestationType, userId string) ([]*Policy, error) {
	if !m.CheckPolicyAttestationType(attestationType) {
		return nil, fmt.Errorf("attestation type %s in not support", attestationType)
	}

	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_POLICY)
	var policies []*Policy
	cond := orm.NewCondition().And("AttestationType", attestationType).And("userId", userId)
	qs = qs.SetCond(cond)

	_, err := qs.OrderBy("-updateTime", "-createTime").All(&policies)
	if err != nil {
		logs.Error("Get policy Info list from db,error:%s", err.Error())
		return nil, err
	}

	logs.Info("Get policy of Info list from db success", attestationType)

	return policies, nil
}

func (m *policyModel) GetLatestPolicy(attestationType string) (*Policy, error) {
	if !m.CheckPolicyAttestationType(attestationType) {
		return nil, fmt.Errorf("attestation type %s in not support", attestationType)
	}
	var policy Policy
	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_POLICY)
	cond := orm.NewCondition().And("AttestationType", attestationType)
	qs = qs.SetCond(cond)
	err := qs.OrderBy("-updateTime").Limit(1).One(&policy)
	if err != nil {
		return nil, err
	}
	return &policy, nil
}

func (m *policyModel) CheckPolicyAttestationType(attestationType string) bool {
	if attestationType != NodeType && attestationType != ClusterType {
		return false
	}
	return true
}
