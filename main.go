package main

import (
	"fmt"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/sirupsen/logrus"
	"tcas/initial"
	"tcas/routers"
)

func main() {

	initial.InitLog()
	initial.TeesInit()
	initial.InitDbSqlite()
	initial.EndorsementInit()
	initial.InitNonceManger()

	port := beego.AppConfig.DefaultString("ServerPort", "8080")
	logrus.Info("tcas is running on port: ", port)
	err := routers.InitRouters().Run(fmt.Sprintf(":%s", port))
	if err != nil {
		panic("start server failed, error: " + err.Error())
	}
}
