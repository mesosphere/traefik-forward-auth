package log

import (
	"os"

	"github.com/sirupsen/logrus"
)

func NewDefaultLogger(level, format string) logrus.FieldLogger {
	// Setup logger
	log := logrus.StandardLogger()
	logrus.SetOutput(os.Stdout)

	// Set logger format
	switch format {
	case "pretty":
		break
	case "json":
		logrus.SetFormatter(&logrus.JSONFormatter{})
	// "text" is the default
	default:
		logrus.SetFormatter(&logrus.TextFormatter{
			DisableColors: true,
			FullTimestamp: true,
		})
	}

	// Set logger level
	switch level {
	case "trace":
		logrus.SetLevel(logrus.TraceLevel)
	case "debug":
		logrus.SetLevel(logrus.DebugLevel)
	case "info":
		logrus.SetLevel(logrus.InfoLevel)
	case "error":
		logrus.SetLevel(logrus.ErrorLevel)
	case "fatal":
		logrus.SetLevel(logrus.FatalLevel)
	case "panic":
		logrus.SetLevel(logrus.PanicLevel)
	// warn is the default
	default:
		logrus.SetLevel(logrus.WarnLevel)
	}

	return log
}
