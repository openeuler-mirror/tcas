package endorsement

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"os"
	"path"
	certsmanager "tcas/pki"
	"tcas/util/file"
)

var (
	ECPrivateKey *ecdsa.PrivateKey
	CAJWK        jwk.Key
)

const (
	issuer = "datakeeper"
)

func readKey(filename string) []byte {
	// read the raw contents of the file
	data, err := os.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	return data
}

func InitRootCA(caPath, confPath string) error {
	if !file.Exists(path.Join(caPath, "existed")) {
		if err := certsmanager.GenerateCaCerts(caPath, confPath); err != nil {
			logs.Error("generate ca certs failed, error: %s", err.Error())
			return err
		}
		err := os.WriteFile(path.Join(caPath, "existed"), []byte("existed"), os.ModePerm)
		if err != nil {
			os.RemoveAll(caPath)
			return fmt.Errorf("mark ca existed faield, error: %s", err.Error())
		}
	} else {
		logs.Info("root ca is already init")
	}

	var err error
	ECPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(readKey(path.Join(caPath, "private.key")))
	if err != nil {
		return err
	}

	CAJWK, err = GetCAInJWKFormat(caPath)
	if err != nil {
		return err
	}

	return nil
}

func GetCAInJWKFormat(caPath string) (jwk.Key, error) {
	pemData, err := os.ReadFile(path.Join(caPath, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("failed to read the file: %w", err)
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse the PEM block containing the public key")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	publicKey := cert.PublicKey

	key, err := jwk.New(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}
	kid := fmt.Sprintf("%x", md5.Sum(pemData))
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	encodedCert := base64.StdEncoding.EncodeToString(block.Bytes)
	if err := key.Set("x5c", []string{encodedCert}); err != nil {
		return nil, fmt.Errorf("failed to set x5c: %w", err)
	}

	if err := key.Set(jwk.AlgorithmKey, cert.PublicKeyAlgorithm.String()); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	return key, nil
}
