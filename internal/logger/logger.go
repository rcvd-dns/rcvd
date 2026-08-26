// SPDX-License-Identifier: MIT
package logger

import (
	"io"
	"log"
	"os"
	"strings"
)

// Level is an ordered logging severity. Lower values are more verbose.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

// parseLevel maps a config string ("debug"/"info"/"warn"/"error") to a Level.
// Unknown or empty values default to LevelInfo — the historical default.
func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// Logger wraps log.Logger for consistent logging.
//
// The embedded *log.Logger is retained so existing call sites that hold a plain
// *log.Logger keep working unchanged (they log unconditionally, as before). The
// leveled methods below (Debugf/Infof/…) honor the configured Level and are the
// path new/opt-in-quiet call sites use — starting with the DoQ idle-gap retry.
// The global reclassification of every call site onto these methods is a separate,
// tracked follow-up.
type Logger struct {
	*log.Logger
	level Level
}

// New creates a new Logger. level is one of "debug"/"info"/"warn"/"error"
// (default: info). It now actually gates the leveled methods — previously the
// argument was accepted and discarded.
func New(level string, w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{
		Logger: log.New(w, "", log.LstdFlags|log.Lshortfile),
		level:  parseLevel(level),
	}
}

// NewDefault creates a logger with default settings (info level, stderr).
func NewDefault() *Logger {
	return New("info", os.Stderr)
}

// Level returns the configured severity threshold.
func (l *Logger) Level() Level { return l.level }

// Enabled reports whether a message at lvl would be emitted at the current level.
func (l *Logger) Enabled(lvl Level) bool { return lvl >= l.level }

// Debugf logs at debug level (suppressed unless [logging] level = "debug").
func (l *Logger) Debugf(format string, args ...any) {
	if l.Enabled(LevelDebug) {
		l.Logger.Printf(format, args...)
	}
}

// Infof logs at info level (the default threshold).
func (l *Logger) Infof(format string, args ...any) {
	if l.Enabled(LevelInfo) {
		l.Logger.Printf(format, args...)
	}
}

// Warnf logs at warn level.
func (l *Logger) Warnf(format string, args ...any) {
	if l.Enabled(LevelWarn) {
		l.Logger.Printf(format, args...)
	}
}

// Errorf logs at error level (always emitted at the default threshold and below).
func (l *Logger) Errorf(format string, args ...any) {
	if l.Enabled(LevelError) {
		l.Logger.Printf(format, args...)
	}
}
