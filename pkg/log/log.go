package log

import (
	ltsv "github.com/hnakamur/zap-ltsv"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var Logger *zap.Logger

func Init(dev bool) error {
	logCfg := ltsv.NewProductionConfig()
	logCfg.DisableCaller = !dev
	logCfg.EncoderConfig.NameKey = "loc"
	logCfg.EncoderConfig.LevelKey = "lvl"
	logCfg.EncoderConfig.EncodeDuration = zapcore.StringDurationEncoder
	logCfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	logCfg.Development = dev

	if dev {
		logCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	err := ltsv.RegisterLTSVEncoder()
	if err != nil {
		return err
	}

	if l, err := logCfg.Build(); err != nil {
		return err
	} else {
		Logger = l
		return nil
	}
}
