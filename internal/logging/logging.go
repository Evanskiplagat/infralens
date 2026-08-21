package logging

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Level controls which log entries are emitted.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var levelNames = map[string]Level{
	"debug": LevelDebug,
	"info":  LevelInfo,
	"warn":  LevelWarn,
	"error": LevelError,
}

// Logger emits structured-enough stderr log lines for CLI operations.
type Logger struct {
	min Level
	mu  sync.Mutex
}

// New returns a logger for level. An empty level defaults to info.
func New(level string) (Logger, error) {
	if level == "" {
		level = "info"
	}
	min, ok := levelNames[strings.ToLower(level)]
	if !ok {
		return Logger{}, fmt.Errorf("unknown log level %q (want debug, info, warn, or error)", level)
	}
	return Logger{min: min}, nil
}

// Debugf logs a debug message.
func (l Logger) Debugf(format string, args ...any) {
	l.logf(LevelDebug, format, args...)
}

// Infof logs an informational message.
func (l Logger) Infof(format string, args ...any) {
	l.logf(LevelInfo, format, args...)
}

// Warnf logs a warning.
func (l Logger) Warnf(format string, args ...any) {
	l.logf(LevelWarn, format, args...)
}

// Errorf logs an error.
func (l Logger) Errorf(format string, args ...any) {
	l.logf(LevelError, format, args...)
}

func (l Logger) logf(level Level, format string, args ...any) {
	if level < l.min {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	name := "info"
	for k, v := range levelNames {
		if v == level {
			name = k
			break
		}
	}
	fmt.Fprintf(
		os.Stderr,
		"%s %-5s %s\n",
		time.Now().UTC().Format(time.RFC3339),
		strings.ToUpper(name),
		fmt.Sprintf(format, args...),
	)
}
