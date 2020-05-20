package server

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func firstOrEmpty(data []string) string {
	if len(data) == 0 {
		return ""
	}

	return data[0]
}

func accessLog(logger *zap.Logger) func(*gin.Context) {
	return func(c *gin.Context) {
		t := time.Now()

		c.Next()

		duration := time.Since(t)

		logger.Info(
			"handle request",
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.String("req_id", firstOrEmpty(c.Request.Header["X-Request-Id"])),
			zap.String("u_addr", firstOrEmpty(c.Request.Header["X-User-Address"])),
			zap.String("ip", c.ClientIP()),
			zap.String("protocol", c.Request.Proto),
			zap.String("ua", c.Request.UserAgent()),
			zap.Duration("latency", duration),
		)
	}
}
