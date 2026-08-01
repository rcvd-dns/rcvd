// SPDX-License-Identifier: MIT
package logger

import (
	"io"
	"log"
	"os"
)

// Logger wraps log.Logger for consistent logging.
type Logger struct {
	*log.Logger
}

// New creates a new Logger.
func New(level string, w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{
		Logger: log.New(w, "", log.LstdFlags|log.Lshortfile),
	}
}

// NewDefault creates a logger with default settings (info level, stderr).
func NewDefault() *Logger {
	return New("info", os.Stderr)
}
