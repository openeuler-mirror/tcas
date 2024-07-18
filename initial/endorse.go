package initial

import (
	beego "github.com/beego/beego/v2/server/web"
	"tcas/endorsement"
)

func EndorsementInit() {
	endorseMode := beego.AppConfig.DefaultString("EndorseMode", "local")
	caPath := beego.AppConfig.DefaultString("CaPath", "/workplace/encryptedData/endorsement")
	confPath := beego.AppConfig.DefaultString("ConfPath", "conf/endorsement")
	if endorseMode == "local" {
		err := endorsement.InitRootCA(caPath, confPath)
		if err != nil {
			panic(err)
		}
	} else {
		panic("not support yet")
	}
}
