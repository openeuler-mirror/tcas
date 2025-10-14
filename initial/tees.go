package initial

import (
	//_ "tcas/tees/csv"
	_ "tcas/tees/csv"
	_ "tcas/tees/nvidia"
	_ "tcas/tees/tdx"
	_ "tcas/tees/virtcca"

	"github.com/beego/beego/v2/core/logs"
)

func TeesInit() {
	logs.Info("all tee verifiers are loaded")
}
