package initial

import (
	"github.com/sirupsen/logrus"
	//_ "tcas/tees/csv"
	_ "tcas/tees/virtcca"
)

func TeesInit() {
	logrus.Info("all tee verifiers are loaded")
}
