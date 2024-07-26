package initial

import (
	beego "github.com/beego/beego/v2/server/web"
	"tcas/endorsement"
	"tcas/pki"
)

func InitCertManager() {
	confPath := beego.AppConfig.DefaultString("ConfPath", "conf/endorsement")
	certSaveDir := beego.AppConfig.DefaultString("certSaveDir", "/workplace/encryptedData/certs")
	pki.CertManager = pki.NewManager(certSaveDir, confPath, endorsement.CaCert, endorsement.ECPrivateKey)
}
