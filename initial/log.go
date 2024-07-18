package initial

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"path"
	"runtime"
)

func InitLog() {
	logrus.SetLevel(logrus.TraceLevel)
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
		ForceColors:   true,
		CallerPrettyfier: func(f *runtime.Frame) (string, string) {
			filename := path.Base(f.File)
			return "", filename + ":" + fmt.Sprintf("%d", f.Line)
		},
	})
	logrus.SetReportCaller(true)
}
