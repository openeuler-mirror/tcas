package initial

import (
	"crypto/rsa"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/dgrijalva/jwt-go"
	"os"
	"path"
	"tcas/util/encrypt"
	"tcas/util/file"
)

var (
	RsaPrivateKey *rsa.PrivateKey
	RsaPublicKey  *rsa.PublicKey
)

func InitRsaKey() {
	LoginTokenSignKeyDir := beego.AppConfig.DefaultString("LoginTokenSignKeyDir", "./conf/key")
	privateKeyPath := path.Join(LoginTokenSignKeyDir, "rsa-private.pem")
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(readKey(privateKeyPath))
	if err != nil {
		panic(err)
	}
	RsaPrivateKey = privateKey

	publicKeyPath := path.Join(LoginTokenSignKeyDir, "rsa-public.pem")
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(readKey(publicKeyPath))
	if err != nil {
		panic(err)
	}
	RsaPublicKey = publicKey
}

func readKey(filename string) []byte {
	if file.Exists(filename) == false {
		pathdir := path.Dir(filename)
		err := encrypt.GenRsaKey(1024, pathdir)
		if err != nil {
			panic(err)
		}
	}
	// read the raw contents of the file
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	return data
}
