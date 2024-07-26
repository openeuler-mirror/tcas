package endorsement

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"path"
	"tcas/util/file"
	"time"
)

var (
	ECPrivateKey *ecdsa.PrivateKey
	CAJWK        jwk.Key
	CaCert       *x509.Certificate
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
		if err := GenerateCaCerts(caPath, confPath); err != nil {
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
	privateKeyPath := path.Join(caPath, "private.key")
	caCertPath := path.Join(caPath, "ca.crt")
	ECPrivateKey, err = jwt.ParseECPrivateKeyFromPEM(readKey(privateKeyPath))
	if err != nil {
		return err
	}

	CaCert, err = LoadPair(caCertPath, privateKeyPath)
	if err != nil {
		panic(err)
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

// 生成 ECC 私钥
func GenerateECCPrivateKey() (*ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func SaveKeyToFileUsePEM(key *ecdsa.PrivateKey, savePath string) error {
	keyDer, err := x509.MarshalECPrivateKey(key)
	keyBlock := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDer,
	}

	keyData := pem.EncodeToMemory(keyBlock)

	if err = ioutil.WriteFile(savePath, keyData, 0644); err != nil {
		logs.Error("save the private key to %s failed, error: %s", savePath, err.Error())
		return err
	}
	return nil
}

func SaveCertToFileUsePEM(cert *x509.Certificate, savePath string) error {
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(certBlock)

	if err := ioutil.WriteFile(savePath, pemData, 0644); err != nil {
		logs.Error("save the server crt to %s, failed, error: %s", savePath, err.Error())
		return err
	}
	return nil
}

func CreateCertUseECC(csrConf string, privateKey *ecdsa.PrivateKey, isCa bool, parent *x509.Certificate, serverKey *ecdsa.PrivateKey) (*x509.Certificate, error) {
	var csr x509.Certificate

	csrByte, err := ioutil.ReadFile(csrConf)
	if err != nil {
		logs.Error("read csr conf from %s failed, error: %s", csrConf, err.Error())
		return nil, err
	}

	if err := json.Unmarshal(csrByte, &csr); err != nil {
		logs.Error("unmarshl csr conf failed, error: %s", err.Error())
		return nil, err
	}

	if isCa {
		csr.Version = 3
		csr.SerialNumber = big.NewInt(time.Now().Unix())
		csr.NotBefore = time.Now()
		csr.NotAfter = time.Now().AddDate(20, 0, 0)
		csr.BasicConstraintsValid = true
		csr.IsCA = true
		csr.MaxPathLen = 1
		csr.MaxPathLenZero = false
		csr.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		parent = &csr
		serverKey = privateKey
	} else {
		csr.Version = 3
		csr.SerialNumber = big.NewInt(time.Now().Unix())
		csr.NotBefore = time.Now()
		csr.NotAfter = time.Now().AddDate(10, 0, 0)
		csr.BasicConstraintsValid = true
		csr.IsCA = false
		csr.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		csr.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		if parent == nil {
			logs.Error("create server cert must provider parent cert")
			return nil, fmt.Errorf("create server cert must provider parent cert")
		}

		if serverKey == nil {
			logs.Error("create server cert must provider serverKey")
			return nil, fmt.Errorf("create server cert must provider serverKey")
		}

	}

	der, err := x509.CreateCertificate(rand.Reader, &csr, parent, serverKey.Public(), privateKey)
	if err != nil {
		logs.Error("create cert failed, error: %s\n", err.Error())
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		log.Printf("parse cert faield, error: %s", err.Error())
		return nil, err
	}
	return cert, nil
}

func LoadPair(certFile, keyFile string) (cert *x509.Certificate, err error) {
	if len(certFile) == 0 && len(keyFile) == 0 {
		return nil, errors.New("cert or key has not provided")
	}
	// load cert and key by tls.LoadX509KeyPair
	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return
	}

	cert, err = x509.ParseCertificate(tlsCert.Certificate[0])
	return
}

func GenerateCaCerts(caSavePath, confPath string) error {
	var PrivateKey *ecdsa.PrivateKey
	var CaCert *x509.Certificate
	var err error

	if !file.IsDir(caSavePath) {
		if err := os.MkdirAll(caSavePath, os.ModePerm); err != nil {
			return err
		}
	}

	caCertPath := path.Join(caSavePath, "ca.crt")
	privateKeyPath := path.Join(caSavePath, "private.key")
	logs.Info("begin to generate new pair of ca and server certs, use csr confs in %s", confPath)
	if file.IsFile(caCertPath) && file.IsFile(privateKeyPath) {
		logs.Info("ca certs is already generate\n")
		return nil
	}

	PrivateKey, err = GenerateECCPrivateKey()
	if err != nil {
		return err
	}

	caConf := path.Join(confPath, "ca-csr.json")
	CaCert, err = CreateCertUseECC(caConf, PrivateKey, true, nil, nil)
	if err != nil {
		return err
	}

	if err := SaveCertToFileUsePEM(CaCert, caCertPath); err != nil {
		return err
	}
	logs.Info("ca.crt generate successful, save in %s", caCertPath)

	if err := SaveKeyToFileUsePEM(PrivateKey, privateKeyPath); err != nil {
		return err
	}
	logs.Info("private.key generate successful, save in %s", privateKeyPath)

	return nil
}
