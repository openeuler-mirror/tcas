package initial

import (
	beego "github.com/beego/beego/v2/server/web"
	"tcas/apprasisal"
)

func InitNonceManger() {
	NonceLifeTime := beego.AppConfig.DefaultInt("NonceLifeTime", 3)
	apprasisal.GNonceManager = apprasisal.NewNonceManager(NonceLifeTime)
}
