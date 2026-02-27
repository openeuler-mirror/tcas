package models

import (
	"crypto/sha256"
	"fmt"
	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	"github.com/google/uuid"
	"strings"
	"time"
)

const NodeType = "trust_node"
const ClusterType = "trust_cluster"

var PolicyModel *policyModel

func init() {
	orm.RegisterModel(new(Policy))
	orm.RegisterModel(new(Cluster))
	orm.RegisterModel(new(PolicyHistory))
	PolicyModel = &policyModel{}
}

type policyModel struct{}

type Cluster struct {
	No         int       `orm:"auto" json:"no"`
	Id         string    `orm:"unique;size(255)" json:"cluster_id"`
	Name       string    `orm:"size(255)" json:"cluster_name"`
	UserId     string    `orm:"size(255)" json:"user_id"`
	CreateTime time.Time `orm:"auto_now_add;type(datetime)" json:"create_time"`
}

func (u *Cluster) TableUnique() [][]string {
	return [][]string{
		[]string{"UserId", "Name"},
	}
}

func (u *Cluster) TableName() string {
	return TABLE_CLUSTER
}

type PolicyHistory struct {
	Id          int       `orm:"auto" json:"no"`
	HistoryId   string    `orm:"unique;size(255)" json:"history_id"`
	PolicyId    string    `orm:"size(255)" json:"policy_id"`
	ClusterId   string    `orm:"size(255)" json:"cluster_id"`
	UserId      string    `orm:"size(255)" json:"user_id"`
	Rego        string    `orm:"type(text)" json:"rego"`
	Signature   string    `orm:"size(255)" json:"signature"`
	Version     int       `orm:"size(10)" json:"version"`
	Description string    `orm:"size(255)" json:"desc"`
	CreateTime  time.Time `orm:"auto_now_add;type(datetime)" json:"create_time"`
}

func (u *PolicyHistory) TableName() string {
	return TABLE_POLICY_HISTORY
}

type Policy struct {
	No              int        `orm:"auto" json:"no,omitempty"`
	Id              string     `orm:"unique;size(255)" json:"policy_id,omitempty"`
	Rego            string     `orm:"size(2048)" json:"policy_rego,omitempty"`
	Name            string     `orm:"size(200)" json:"policy_name,omitempty"`
	AttestationType string     `orm:"size(255)" json:"attestation_type,omitempty"`
	Hash            string     `orm:"size(255)" json:"policy_hash,omitempty"`
	Signature       string     `orm:"size(255)" json:"policy_signature,omitempty"`
	Version         int        `orm:"size(255)" json:"version,omitempty"`
	UserId          string     `orm:"size(255)" json:"userId,omitempty"`
	ClusterId       string     `orm:"size(255)" json:"cluster_id,omitempty"`
	CreateTime      *time.Time `orm:"auto_now_add;type(datetime)" json:"createTime,omitempty"`
	UpdateTime      *time.Time `orm:"auto_now;type(datetime)" json:"updateTime,omitempty"`
}

func (u *Policy) TableUnique() [][]string {
	return [][]string{
		[]string{"ClusterId", "Name"},
	}
}

func (u *Policy) TableName() string {
	return TABLE_POLICY
}

func (m *policyModel) CreateCluster(name, userId string) (string, error) {
	o := orm.NewOrm()

	existCluster := Cluster{}
	err := o.QueryTable(TABLE_CLUSTER).
		Filter("Name", name).
		Filter("UserId", userId).
		One(&existCluster)

	if err == nil {
		return "", fmt.Errorf("cluster name '%s' already exists", name)
	} else if err != orm.ErrNoRows {
		return "", err
	}

	cluster := &Cluster{
		Id:     uuid.New().String(),
		Name:   name,
		UserId: userId,
	}
	_, err = o.Insert(cluster)
	if err != nil {
		return "", err
	}
	return cluster.Id, nil
}

func (m *policyModel) GetClusterById(clusterId string) (*Cluster, error) {
	v := new(Cluster)
	if err := orm.NewOrm().QueryTable(TABLE_CLUSTER).Filter("Id", clusterId).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (m *policyModel) AddPolicy(p *Policy) (id string, err error) {
	o := orm.NewOrm()

	if p.ClusterId != "" {
		clusterExist := Cluster{Id: p.ClusterId}
		if err := o.Read(&clusterExist, "Id"); err != nil {
			return "", fmt.Errorf("target cluster does not exist")
		}

		existPolicy := Policy{}
		err = o.QueryTable(TABLE_POLICY).
			Filter("ClusterId", p.ClusterId).
			Filter("Name", p.Name).
			One(&existPolicy)

		if err == nil {
			return "", fmt.Errorf("policy name '%s' already exists in this cluster", p.Name)
		} else if err != orm.ErrNoRows {
			return "", err
		}
	}

	p.Id = uuid.New().String()
	p.Version = 1
	p.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(p.Rego)))
	if p.AttestationType == "" {
		p.AttestationType = NodeType
	}

	if p.AttestationType != NodeType && p.AttestationType != ClusterType {
		return "", fmt.Errorf("attestation type is not support")
	}

	to, err := o.Begin()
	if err != nil {
		return "", err
	}

	commit := false
	defer func() {
		if !commit {
			_ = to.Rollback()
			return
		}
		if commitErr := to.Commit(); commitErr != nil {
			err = commitErr
		}
	}()

	// 插入策略表
	_, err = to.Insert(p)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return "", fmt.Errorf("policy name '%s' already exists in this cluster (concurrency detected)", p.Name)
		}
		return "", err
	}

	// 插入历史表
	history := &PolicyHistory{
		HistoryId:   uuid.New().String(),
		PolicyId:    p.Id,
		ClusterId:   p.ClusterId,
		UserId:      p.UserId,
		Rego:        p.Rego,
		Signature:   p.Signature,
		Version:     p.Version,
		Description: "create",
	}

	_, err = to.Insert(history)
	if err != nil {
		return "", err
	}

	commit = true
	return p.Id, nil
}

func (m *policyModel) GetPolicyById(id string) (v *Policy, err error) {
	v = new(Policy)
	if err = orm.NewOrmUsingDB("default").QueryTable(TABLE_POLICY).Filter("Id", id).One(v); err != nil {
		return nil, err
	}
	return v, nil
}

func (m *policyModel) UpdatePolicyById(mp *Policy) (err error) {
	o := orm.NewOrm()
	v := &Policy{Id: mp.Id}

	if err = o.Read(v, "Id"); err != nil {
		return err
	}

	hasChanged := false
	if mp.Rego != "" && mp.Rego != v.Rego {
		v.Rego = mp.Rego
		v.Hash = fmt.Sprintf("%x", sha256.Sum256([]byte(mp.Rego)))
		hasChanged = true
	}

	if mp.Signature != "" && mp.Signature != v.Signature {
		v.Signature = mp.Signature
		hasChanged = true
	}

	if mp.Name != "" && mp.Name != v.Name {
		v.Name = mp.Name
		hasChanged = true
	}

	if mp.ClusterId != "" && mp.ClusterId != v.ClusterId {
		v.ClusterId = mp.ClusterId
		hasChanged = true
	}

	if !hasChanged {
		return nil
	}

	v.Version = v.Version + 1
	to, err := o.Begin()
	if err != nil {
		return err
	}
	commit := false
	defer func() {
		if !commit {
			_ = to.Rollback()
			return
		}
		if commitErr := to.Commit(); commitErr != nil {
			err = commitErr
		}
	}()

	_, err = to.Update(v)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return fmt.Errorf("the target policy name or cluster setting causes a conflict")
		}
		return err
	}

	history := &PolicyHistory{
		HistoryId:   uuid.New().String(),
		PolicyId:    v.Id,
		ClusterId:   v.ClusterId,
		UserId:      v.UserId,
		Rego:        v.Rego,
		Signature:   v.Signature,
		Version:     v.Version,
		Description: "update",
	}

	_, err = to.Insert(history)
	if err != nil {
		return err
	}

	commit = true
	return nil
}

func (m *policyModel) DeletePolicy(id string) (err error) {
	o := orm.NewOrm()
	v := &Policy{Id: id}
	if err = o.Read(v, "Id"); err != nil {
		return err
	}

	to, err := o.Begin()
	if err != nil {
		return err
	}

	commit := false
	defer func() {
		if !commit {
			_ = to.Rollback()
			return
		}
		if commitErr := to.Commit(); commitErr != nil {
			err = commitErr
		}
	}()

	history := &PolicyHistory{
		HistoryId:   uuid.New().String(),
		PolicyId:    v.Id,
		ClusterId:   v.ClusterId,
		UserId:      v.UserId,
		Rego:        v.Rego,
		Signature:   v.Signature,
		Version:     v.Version,
		Description: "delete",
	}

	_, err = to.Insert(history)
	if err != nil {
		return err
	}

	_, err = to.Delete(v)
	if err != nil {
		return err
	}

	commit = true
	return nil
}

func (m *policyModel) GetPolicies(attestationType, userId string) ([]*Policy, error) {
	if !m.CheckPolicyAttestationType(attestationType) {
		return nil, fmt.Errorf("attestation type %s in not support", attestationType)
	}

	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_POLICY)
	var policies []*Policy
	cond := orm.NewCondition().And("AttestationType", attestationType).And("UserId", userId)
	qs = qs.SetCond(cond)

	_, err := qs.OrderBy("-UpdateTime", "-CreateTime").All(&policies)
	if err != nil {
		logs.Error("Get policy Info list from db,error:%s", err.Error())
		return nil, err
	}

	logs.Info("Get policy of Info list from db success", attestationType)

	return policies, nil
}

func (m *policyModel) GetLatestPolicy(attestationType, userId string) (*Policy, error) {
	if !m.CheckPolicyAttestationType(attestationType) {
		return nil, fmt.Errorf("attestation type %s in not support", attestationType)
	}
	var policy Policy
	o := orm.NewOrm()
	qs := o.QueryTable(TABLE_POLICY)
	cond := orm.NewCondition().And("AttestationType", attestationType).And("UserId", userId)
	qs = qs.SetCond(cond)
	err := qs.OrderBy("-UpdateTime").Limit(1).One(&policy)
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

func (m *policyModel) GetPolicyHistoryById(historyId string) (*PolicyHistory, error) {
	v := new(PolicyHistory)
	err := orm.NewOrm().QueryTable(TABLE_POLICY_HISTORY).Filter("HistoryId", historyId).One(v)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func (m *policyModel) GetPoliciesByClusterId(clusterId string) ([]*Policy, error) {
	o := orm.NewOrm()
	var policies []*Policy
	_, err := o.QueryTable(TABLE_POLICY).Filter("ClusterId", clusterId).OrderBy("-CreateTime").All(&policies)
	if err != nil {
		return nil, err
	}
	return policies, nil
}

func (m *policyModel) DeletePolicyFromCluster(clusterId, policyId string) error {
	o := orm.NewOrm()
	v := &Policy{Id: policyId}

	if err := o.Read(v, "Id"); err != nil {
		return err
	}

	if v.ClusterId != clusterId {
		return fmt.Errorf("policy %s does not belong to cluster %s", policyId, clusterId)
	}

	return m.DeletePolicy(policyId)
}
