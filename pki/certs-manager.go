package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	"math/big"
	"net"
	"os"
	"path"
	"time"
)

var CertManager *Manager

type X509Info struct {
	Name        string   `json:"name"`
	CommonName  string   `json:"common_name"`
	DNSNames    []string `json:"dns_names"`
	IPAddresses []string `json:"ip_addresses"`
	Expiration  int      `json:"expiration"`
}

type PKIConf struct {
	CaPath      string
	PKIToolPath string
}

type Manager struct {
	CertSaveDir  string
	CaCert       *x509.Certificate
	CaPrivateKey *ecdsa.PrivateKey
	CSRConfPath  string
}

func NewManager(certSaveDir, cSRConfPath string, CaCert *x509.Certificate, CaPrivateKey *ecdsa.PrivateKey) *Manager {
	return &Manager{
		CertSaveDir:  certSaveDir,
		CaCert:       CaCert,
		CaPrivateKey: CaPrivateKey,
		CSRConfPath:  cSRConfPath,
	}
}

func (m *Manager) GenerateServerCerts(customCsr *X509Info, serverPubKey *ecdsa.PublicKey, token string) (*x509.Certificate, error) {
	serverCsrTemplate := path.Join(m.CSRConfPath, "server-csr.json.template")
	csrByte, err := os.ReadFile(serverCsrTemplate)
	if err != nil {
		logs.Error("read csr conf from %s failed, error: %s", serverCsrTemplate, err.Error())
		return nil, err
	}

	csr := new(x509.Certificate)
	if err := json.Unmarshal(csrByte, csr); err != nil {
		logs.Error("unmarshl csr conf failed, error: %s", err.Error())
		return nil, err
	}

	csr.SerialNumber = big.NewInt(time.Now().Unix())
	csr.NotBefore = time.Now()
	csr.NotAfter = time.Now().AddDate(customCsr.Expiration, 0, 0)
	csr.ExtraExtensions = []pkix.Extension{
		{
			Id:       []int{2, 23, 133, 5, 4, 9}, // OID 2.23.133.5.4.9
			Critical: false,
			Value:    []byte(token), // 扩展的值
		},
	}

	csr.Subject.CommonName = customCsr.CommonName
	for _, d := range customCsr.DNSNames {
		csr.DNSNames = append(csr.DNSNames, d)
	}

	for _, ip := range customCsr.IPAddresses {
		if address := net.ParseIP(ip); address != nil {
			csr.IPAddresses = append(csr.IPAddresses, address)
		} else {
			return nil, fmt.Errorf("ip of %s formate error", ip)
		}
	}

	if address := net.ParseIP(customCsr.CommonName); address != nil {
		csr.IPAddresses = append(csr.IPAddresses, address)
		logs.Debug("ip addresses name is %s", csr.IPAddresses)
	}

	der, err := x509.CreateCertificate(rand.Reader, csr, m.CaCert, serverPubKey, m.CaPrivateKey)
	if err != nil {
		logs.Error("create cert failed, error: %s\n", err.Error())
		return nil, err
	}

	serverCert, err := x509.ParseCertificate(der)
	if err != nil {
		logs.Error("parse cert failed, error: %s", err.Error())
		return nil, err
	}

	customCertSaveDir := path.Join(m.CertSaveDir, fmt.Sprintf("%d", csr.SerialNumber))
	err = os.MkdirAll(customCertSaveDir, os.ModePerm)
	if err != nil {
		logs.Error("create custer cert save dir failed, error: %s", err)
	}

	customCsrSavePath := path.Join(customCertSaveDir, fmt.Sprintf("%s.csr", csr.Subject.CommonName))
	if err := SaveCsrToFileUsePEM(csr, customCsrSavePath); err != nil {
		os.RemoveAll(customCertSaveDir)
		return nil, err
	}
	logs.Info("crs.json generate successful, save in %s", customCsrSavePath)

	customCertSavePath := path.Join(customCertSaveDir, fmt.Sprintf("%s.crt", csr.Subject.CommonName))
	if err := SaveCertToFileUsePEM(serverCert, customCertSavePath); err != nil {
		os.RemoveAll(customCertSaveDir)
		return nil, err
	}
	logs.Info("server.crt generate successful, save in %s", customCertSavePath)

	return serverCert, nil
}

func SaveCertToFileUsePEM(cert *x509.Certificate, savePath string) error {
	certBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	pemData := pem.EncodeToMemory(certBlock)

	if err := os.WriteFile(savePath, pemData, 0644); err != nil {
		logs.Error("save the server crt to %s, failed, error: %s", savePath, err.Error())
		return err
	}
	return nil
}

func SaveCsrToFileUsePEM(csr *x509.Certificate, savePath string) error {
	csrByte, err := json.Marshal(csr)
	if err != nil {
		return fmt.Errorf("marshal csr faieled, error: %s", err)
	}

	err = os.WriteFile(savePath, csrByte, os.ModePerm)
	if err != nil {
		return fmt.Errorf("save csr to %s, failed, error: %s", savePath, err)
	}
	return nil
}

func ParsePublicKeyFromPem(pemData []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing the public key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DER encoded public key: error: %s", err)
	}

	eccpub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key type is not ECDSA")
	}

	return eccpub, nil

}
