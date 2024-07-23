package initial

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"io"
	"os"
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
	logrus.SetOutput(os.Stdout)

	file, err := os.OpenFile("tcas.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	writers := []io.Writer{
		file,
		os.Stdout}

	fileAndStdoutWriter := io.MultiWriter(writers...)
	if err != nil {
		panic(err)
	}
	logrus.SetOutput(fileAndStdoutWriter)

	logrus.SetReportCaller(true)
}
