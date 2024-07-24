package initial

import (
	"fmt"
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"math"
	"os"
)

func InitLog() {
	logDir := beego.AppConfig.DefaultString("LogDir", "logs")
	if err := os.MkdirAll(logDir, os.ModePerm); err != nil {
		panic(err)
	}
	logMaxDays := beego.AppConfig.DefaultInt64("LogMaxDay", math.MaxInt64)
	config := fmt.Sprintf("{\"maxdays\":%d ,\"filename\": \"%s/tcas.log\"}", logMaxDays, logDir)
	if err := logs.SetLogger(logs.AdapterFile, config); err != nil {
		panic(err)
	}
	logs.SetLogger("console")

	level := beego.AppConfig.DefaultInt("LogLevel", logs.LevelDebug)
	if level > logs.LevelDebug {
		logs.Warning("Not support the logLevel config in app.conf, will use default loglevel of debug,only suport 7 debug 6 info 3 error")
		level = logs.LevelDebug
	}

	logs.SetLevel(level)
	logs.EnableFuncCallDepth(true)
}
