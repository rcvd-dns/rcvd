// SPDX-License-Identifier: MIT
package logger

import (
	"io"
	"log"
	"os"
	"strings"
	"time"
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

// TimeLayout returns the Go time layout for an ISO 8601 / RFC 3339 UTC timestamp
// at the requested precision: "second" (default), "ms", or "us". Unknown values
// fall back to second precision. The config layer validates the value up front;
// this fallback only guards direct callers. Examples:
//
//	second: 2008-08-18T13:19:55Z
//	ms:     2008-08-18T13:19:55.000Z
//	us:     2008-08-18T13:19:55.000000Z
//
// The trailing Z is a literal, correct only because timestamps are always
// formatted in UTC (see isoWriter.Write / the zap encoder), where the offset is
// always zero.
func TimeLayout(precision string) string {
	switch precision {
	case "ms":
		return "2006-01-02T15:04:05.000Z"
	case "us":
		return "2006-01-02T15:04:05.000000Z"
	default: // "second"
		return "2006-01-02T15:04:05Z"
	}
}

// isoWriter prepends an ISO 8601 / RFC 3339 UTC timestamp to every line written
// through it, at the configured precision, e.g.
//
//	2008-08-18T13:19:55Z <message>
//
// Go's stdlib log package hard-codes a slash date (2009/01/23) in its flags and
// documents that there is "no control over ... the format they present"
// (https://pkg.go.dev/log#pkg-constants), so no flag can turn it into ISO 8601,
// and the slash form is not date-greppable. Rather than pull in a second logging
// library for rcvd's own lines, we stamp the time here and leave the stdlib
// log.Logger's own date/time flags off. log.Lshortfile is kept (it is appended by
// log after this prefix, before the message).
type isoWriter struct {
	w      io.Writer
	layout string
}

// Unwrap returns the underlying destination writer, without the ISO 8601
// timestamp prefix. The certmagic zap bridge type-asserts for this so it can
// write to the raw destination and supply its own ISO 8601 timestamp, rather
// than double-stamping through isoWriter. Exported indirectly via this method
// so internal/rcvd_tls does not import internal/logger.
func (iw *isoWriter) Unwrap() io.Writer { return iw.w }

func (iw *isoWriter) Write(p []byte) (int, error) {
	stamp := time.Now().UTC().Format(iw.layout) + " "
	if _, err := iw.w.Write([]byte(stamp)); err != nil {
		return 0, err
	}
	// Report the caller's byte count so log.Logger accounting stays correct.
	return iw.w.Write(p)
}

// Logger wraps log.Logger for consistent logging.
//
// The embedded *log.Logger is retained so existing call sites that hold a plain
// *log.Logger keep working unchanged (they log unconditionally, as before). The
// leveled methods below (Debugf/Infof/…) honor the configured Level and are the
// path new/opt-in-quiet call sites use — starting with the DoQ idle-gap retry.
// The global reclassification of every call site onto these methods is a separate,
// tracked follow-up.
//
// All lines carry an ISO 8601 / RFC 3339 timestamp (see isoWriter), so rcvd's
// output is greppable by date and lines up with certmagic's bridged zap output,
// which is configured for the same format in internal/rcvd_tls/automation.go.
type Logger struct {
	*log.Logger
	level Level
	raw   io.Writer
}

// New creates a new Logger. level is one of "debug"/"info"/"warn"/"error"
// (default: info). timestamp is the ISO 8601 fractional precision —
// "second" (default), "ms", or "us" (see TimeLayout). It now actually gates the
// leveled methods — previously the level argument was accepted and discarded.
func New(level, timestamp string, w io.Writer) *Logger {
	if w == nil {
		w = os.Stderr
	}
	return &Logger{
		// No stdlib date/time flags (see isoWriter): isoWriter supplies the
		// ISO 8601 stamp the log package's own flags cannot produce.
		Logger: log.New(&isoWriter{w: w, layout: TimeLayout(timestamp)}, "", log.Lshortfile),
		level:  parseLevel(level),
		raw:    w,
	}
}

// NewDefault creates a logger with default settings (info level, second
// precision, stderr).
func NewDefault() *Logger {
	return New("info", "second", os.Stderr)
}

// RawWriter returns the underlying destination writer, without the ISO 8601
// timestamp prefix that isoWriter adds. certmagic's bridged zap logger writes
// here and supplies its own ISO 8601 timestamp, so the two do not double-stamp.
func (l *Logger) RawWriter() io.Writer { return l.raw }

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
