package controllers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/beego/beego/v2/client/orm"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"tcas/apprasisal"
	"tcas/consts"
	"tcas/models"
)

// ClusterAttestationController intentionally uses no authentication for now.
// Cluster policy management continues to use its existing authentication.
type ClusterAttestationController struct {
	beego.Controller
}

type clusterAttestationResponse struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
}

func (c *ClusterAttestationController) respond(status, code int, message, token string) {
	c.Ctx.Output.SetStatus(status)
	c.Data["json"] = clusterAttestationResponse{Code: strconv.Itoa(code), Message: message, Token: token}
	c.ServeJSON()
}

func (c *ClusterAttestationController) clusterPolicies(clusterID string) ([]*models.Policy, bool) {
	if strings.TrimSpace(clusterID) == "" {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE__PARAMETER_ERROR, "cluster_id is required", "")
		return nil, false
	}
	if _, err := models.PolicyModel.GetClusterById(clusterID); err != nil {
		if errors.Is(err, orm.ErrNoRows) {
			c.respond(http.StatusBadRequest, consts.ERROR_CODE_GET_CLUSTER_POLICY_FAILED, "cluster not found", "")
		} else {
			logs.Error("load cluster failed: %v", err)
			c.respond(http.StatusInternalServerError, consts.ERROR_CODE_GET_CLUSTER_POLICY_FAILED, "failed to load cluster", "")
		}
		return nil, false
	}
	policies, err := models.PolicyModel.GetPoliciesByClusterId(clusterID)
	if err != nil {
		logs.Error("load cluster policies failed: %v", err)
		c.respond(http.StatusInternalServerError, consts.ERROR_CODE_GET_CLUSTER_POLICY_FAILED, "failed to load cluster policies", "")
		return nil, false
	}
	return policies, true
}

func (c *ClusterAttestationController) AttestCluster() {
	var request apprasisal.ClusterRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &request); err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, "invalid JSON request", "")
		return
	}
	if err := request.Validate(); err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE__PARAMETER_ERROR, err.Error(), "")
		return
	}
	policies, ok := c.clusterPolicies(request.ClusterIDs[0])
	if !ok {
		return
	}
	signed, err := apprasisal.ClusterAppraisal(c.Ctx.Request.Context(), &request, policies)
	if err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE_ATTEST_CLUSTER_FAILED, err.Error(), "")
		return
	}
	c.respond(http.StatusOK, http.StatusOK, "attest successful", signed)
}

func (c *ClusterAttestationController) AttestClusterNode() {
	var request apprasisal.ClusterNodeRequest
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &request); err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE__JSON__UNMARSHAL_FAILED, "invalid JSON request", "")
		return
	}
	if err := request.Validate(); err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE__PARAMETER_ERROR, err.Error(), "")
		return
	}
	clusterID := c.Ctx.Input.Param(":cluster_id")
	policies, ok := c.clusterPolicies(clusterID)
	if !ok {
		return
	}
	signed, err := apprasisal.ClusterNodeAppraisal(c.Ctx.Request.Context(), clusterID, &request, policies)
	if err != nil {
		c.respond(http.StatusBadRequest, consts.ERROR_CODE_ATTEST_CLUSTER_NODE_FAILED, err.Error(), "")
		return
	}
	c.respond(http.StatusOK, http.StatusOK, "attest successful", signed)
}
