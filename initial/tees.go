package initial

import (
	"github.com/sirupsen/logrus"
	_ "tcas/tees/csv"
)

func TeesInit() {
	logrus.Info("all tee verifiers are loaded")
}
