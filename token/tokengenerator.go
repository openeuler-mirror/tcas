package token

import (
	"fmt"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	"tcas/endorsement"
	"tcas/util/convertor"
	"time"
)

type EATInfo struct {
	Dbgstat    string `json:"dbgstat"`
	EATProfile string `json:"eat_profile"`
	Intuse     string `json:"intuse"`
}

type JwtCommonClaims struct {
	jwt.StandardClaims
	EATInfo
}

func GenerateToken(customerClaims map[string]interface{}) (string, error) {
	// default token exp time is 15min.
	expSecond := beego.AppConfig.DefaultInt64("LoginTokenLifeTime", 15)
	//add the limit of token exp time 60min
	if expSecond > 60 {
		expSecond = 60
	}

	jcc := new(JwtCommonClaims)

	now := time.Now()
	jcc.StandardClaims = jwt.StandardClaims{
		ExpiresAt: now.Add(time.Duration(expSecond) * time.Minute).Unix(),
		Id:        uuid.NewString(),
		IssuedAt:  now.Unix(),
		Issuer:    "trust cluster attestation server",
		NotBefore: now.Unix() - 1000,
	}

	jcc.EATInfo = EATInfo{
		Dbgstat:    "disabled",
		Intuse:     "generic",
		EATProfile: "not support yet",
	}

	jccMap, err := convertor.AnyToMap(jcc)
	if err != nil {
		return "", fmt.Errorf("conver common claim to map failed, error: %s", err)
	}
	for k, v := range jccMap {
		customerClaims[k] = v
	}

	jwtMap := jwt.MapClaims{}
	jwtMap = customerClaims
	token := jwt.New(jwt.SigningMethodES256)
	token.Claims = jwtMap
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
