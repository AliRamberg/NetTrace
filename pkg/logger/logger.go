package logger

import (
	"fmt"
	"os"
	"sync"

	"go.uber.org/zap"
)

var (
	once   sync.Once
	logger *zap.SugaredLogger
)

func Get() *zap.SugaredLogger {
	once.Do(func() {

		config := zap.NewProductionConfig()

		config.EncoderConfig.TimeKey = ""
		config.EncoderConfig.CallerKey = ""
		config.EncoderConfig.MessageKey = "message"
		config.Encoding = "console"
		config.EncoderConfig.StacktraceKey = ""
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)

		zapLogger, err := config.Build()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create logger: %s\n", err.Error())
		}
		logger = zapLogger.Sugar()
	})

	return logger
}
