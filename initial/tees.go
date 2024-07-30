package initial

import (
	//_ "tcas/tees/csv"
	"github.com/beego/beego/v2/core/logs"
	_ "tcas/tees/csv"
	_ "tcas/tees/virtcca"
)

func TeesInit() {
	logs.Info("all tee verifiers are loaded")
}
