package apprasisal

import (
	"fmt"
	"github.com/google/uuid"
	"strings"
	"tcas/models"
	"time"
)

var GNonceManager *NonceManager

type NonceManager struct {
	NonceLifeTime int
}

func NewNonceManager(nonceLifeTime int) *NonceManager {
	return &NonceManager{
		NonceLifeTime: nonceLifeTime,
	}
}

func (n *NonceManager) CheckNonce(nonce string) error {
	nonceInfo, err := models.NonceModel.GetNonceById(nonce)
	if err != nil {
		return fmt.Errorf("nonce %s is not exist", nonce)
	}

	if time.Now().After(nonceInfo.CreateTime.Add(time.Duration(n.NonceLifeTime) * time.Minute)) {
		return fmt.Errorf("nonce is expired")
	}

	return nil
}

func (n *NonceManager) GenerateNonce() (*models.Nonce, error) {
	p := &models.Nonce{
		Id:          strings.ReplaceAll(uuid.New().String(), "-", ""),
		ExpiredTime: time.Now().Add(time.Duration(n.NonceLifeTime) * time.Minute),
	}
	_, err := models.NonceModel.AddNonce(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}
