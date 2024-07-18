package token

import (
	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"tcas/endorsement"
	"time"
)

type EATInfo struct {
	Dbgstat    string `json:"dbgstat"`
	EATProfile string `json:"eat_profile"`
	Intuse     string `json:"intuse"`
}

type JwtClaims struct {
	jwt.StandardClaims
	EATInfo
	CustomerClaims map[string]interface{}
}

func GenerateToken(customerClaims map[string]interface{}) (string, error) {
	// default token exp time is 15min.
	expSecond := beego.AppConfig.DefaultInt64("LoginTokenLifeTime", 15)
	//add the limit of token exp time 60min
	if expSecond > 60 {
		expSecond = 60
	}

	jbc := new(JwtClaims)

	now := time.Now()
	jbc.StandardClaims = jwt.StandardClaims{
		ExpiresAt: now.Add(time.Duration(expSecond) * time.Minute).Unix(),
		Id:        uuid.NewString(),
		IssuedAt:  now.Unix(),
		Issuer:    "trust cluster attestation server",
		NotBefore: now.Unix() - 1000,
	}

	jbc.EATInfo = EATInfo{
		Dbgstat:    "disabled",
		Intuse:     "generic",
		EATProfile: "not support yet",
	}

	jbc.CustomerClaims = customerClaims

	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = jbc
	token.Header = map[string]interface{}{
		"typ": "JWT",
		"alg": token.Method.Alg(),
		"jku": beego.AppConfig.DefaultString("CAURL", "http://127.0.0.1:8080/v1/pki/ca"),
		"kid": endorsement.CAJWK.KeyID(),
	}

	signedToken, err := token.SignedString(endorsement.ECPrivateKey)
	if err != nil {
		return "", err
	}
	return signedToken, nil
}
