package controllers

import (
	"encoding/base64"
	"encoding/json"
	"tcas/consts"
	"tcas/models"

	"github.com/beego/beego/v2/core/logs"
)

type ClusterController struct {
	DefaultController
}

type ClusterBaseRes struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type CreateClusterReq struct {
	ClusterName string `json:"cluster_name"`
}
type CreateClusterResp struct {
	ClusterBaseRes
	ClusterId string `json:"cluster_id"`
}

func (c *ClusterController) CreateCluster() {
	if !models.HasPolicyPermission(c.User.Roles) {
		c.HandleErrorStatusUnauthorized(401, "no permission", "")
		return
	}

	var req CreateClusterReq
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, "json format error", "")
		return
	}

	if req.ClusterName == "" {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "cluster_name is required", "")
		return
	}

	id, err := models.PolicyModel.CreateCluster(req.ClusterName, c.User.Id)
	if err != nil {
		logs.Error("create cluster failed: %v", err)
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_CLUSTER_FAILED, err.Error(), "")
		return
	}

	c.Data["json"] = CreateClusterResp{
		ClusterBaseRes: ClusterBaseRes{Code: "200", Message: "success"},
		ClusterId:      id,
	}
	c.ServeJSON()
}

type AddClusterPolicyReq struct {
	PolicyRego string `json:"policy_rego"`
	PolicyName string `json:"policy_name"`
}
type AddClusterPolicyResp struct {
	ClusterBaseRes
	PolicyId string `json:"policy_id"`
}

func (c *ClusterController) AddPolicyToCluster() {
	if !models.HasPolicyPermission(c.User.Roles) {
		c.HandleErrorStatusUnauthorized(401, "no permission", "")
		return
	}

	clusterId := c.Ctx.Input.Param(":cluster_id")
	if clusterId == "" {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "cluster_id is required in url", "")
		return
	}

	var req AddClusterPolicyReq
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &req); err != nil {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, "json format error", "")
		return
	}

	if req.PolicyRego == "" || req.PolicyName == "" {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "policy_rego and policy_name are required", "")
		return
	}

	// 增加对 policy_rego 的 Base64 格式校验，防止非法数据写入导致后续解析崩溃
	if _, err := base64.StdEncoding.DecodeString(req.PolicyRego); err != nil {
		logs.Error("policy_rego is not valid base64: %v", err)
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "policy_rego must be valid base64 format", "")
		return
	}

	// 检查 cluster 是否属于当前用户
	cluster, err := models.PolicyModel.GetClusterById(clusterId)
	if err != nil {
		c.HandleErrorStatusBadRequest(401, "cluster not found", "")
		return
	}
	if cluster.UserId != c.User.Id {
		c.HandleErrorStatusUnauthorized(401, "no permission", "")
		return
	}

	policy := models.Policy{
		Name:            req.PolicyName,
		Rego:            req.PolicyRego,
		ClusterId:       clusterId,
		UserId:          c.User.Id,
		AttestationType: models.ClusterType,
	}

	id, err := models.PolicyModel.AddPolicy(&policy)
	if err != nil {
		logs.Error("add policy to cluster failed: %v", err)
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_CREATE_POLICY_FAILED, err.Error(), "")
		return
	}

	c.Data["json"] = AddClusterPolicyResp{
		ClusterBaseRes: ClusterBaseRes{Code: "200", Message: "success"},
		PolicyId:       id,
	}
	c.ServeJSON()
}

type RemovePolicyResp struct {
	ClusterBaseRes
	PolicyId string `json:"policy_id"`
}

func (c *ClusterController) RemovePolicyFromCluster() {
	if !models.HasPolicyPermission(c.User.Roles) {
		c.HandleErrorStatusUnauthorized(401, "no permission", "")
		return
	}

	clusterId := c.Ctx.Input.Param(":cluster_id")
	policyId := c.Ctx.Input.Param(":policy_id")

	if clusterId == "" || policyId == "" {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "cluster_id and policy_id is required in url", "")
		return
	}

	cluster, err := models.PolicyModel.GetClusterById(clusterId)
	if err != nil {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "cluster not found", "")
		return
	}
	if cluster.UserId != c.User.Id {
		c.HandleErrorStatusUnauthorized(401, "no permission to access this cluster", "")
		return
	}

	policy, err := models.PolicyModel.GetPolicyById(policyId)
	if err != nil {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_DELETE_POLICY_FAILED, "policy not found", "")
		return
	}
	if policy.UserId != c.User.Id || policy.ClusterId != clusterId {
		c.HandleErrorStatusUnauthorized(401, "no permission to delete this policy", "")
		return
	}

	err = models.PolicyModel.DeletePolicyFromCluster(clusterId, policyId)
	if err != nil {
		logs.Error("delete policy failed: %v", err)
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_DELETE_POLICY_FAILED, "delete failed", "")
		return
	}

	c.Data["json"] = RemovePolicyResp{
		ClusterBaseRes: ClusterBaseRes{Code: "200", Message: "success"},
		PolicyId:       policyId,
	}
	c.ServeJSON()
}

type ClusterPolicyItem struct {
	Rego       string `json:"rego"`
	PolicyId   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
}
type GetClusterPoliciesResp struct {
	ClusterBaseRes
	PolicyGroup []ClusterPolicyItem `json:"policygroup"`
}

func (c *ClusterController) GetClusterPolicies() {
	if !models.HasPolicyPermission(c.User.Roles) {
		c.HandleErrorStatusUnauthorized(401, "no permission", "")
		return
	}

	clusterId := c.Ctx.Input.Param(":cluster_id")
	if clusterId == "" {
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE__PARAMETER_ERROR, "cluster_id is required", "")
		return
	}

	cluster, err := models.PolicyModel.GetClusterById(clusterId)
	if err != nil || cluster.UserId != c.User.Id {
		c.HandleErrorStatusUnauthorized(401, "cluster not found or no permission", "")
		return
	}

	list, err := models.PolicyModel.GetPoliciesByClusterId(clusterId)
	if err != nil {
		logs.Error("get policies failed: %v", err)
		c.HandleErrorStatusBadRequest(consts.ERROR_CODE_GET_CLUSTER_POLICY_FAILED, "get failed", "")
		return
	}

	var respList []ClusterPolicyItem
	for _, p := range list {
		respList = append(respList, ClusterPolicyItem{
			Rego:       p.Rego,
			PolicyId:   p.Id,
			PolicyName: p.Name,
		})
	}

	// 确保即使没有策略也返回空数组 `[]`，而不是 `null`
	if respList == nil {
		respList = make([]ClusterPolicyItem, 0)
	}

	c.Data["json"] = GetClusterPoliciesResp{
		ClusterBaseRes: ClusterBaseRes{Code: "200", Message: "success"},
		PolicyGroup:    respList,
	}
	c.ServeJSON()
}
