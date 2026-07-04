// Package logger provides structured logging for CIPHER using zerolog.
// It supports multiple output formats, log levels, and context-aware logging.
package logger

import (
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog"
)

var (
	globalLogger zerolog.Logger
	loggerMu     sync.RWMutex
	loggerOnce   sync.Once
)

// Config holds logger configuration
type Config struct {
	Level        string // debug, info, warn, error
	Format       string // json, console
	Output       string // stdout, stderr, or file path
	EnableCaller bool
}

// DefaultConfig returns default logger configuration
func DefaultConfig() Config {
	return Config{
		Level:        "info",
		Format:       "console",
		Output:       "stdout",
		EnableCaller: false,
	}
}

// Init initializes the global logger with the given configuration
func Init(cfg Config) error {
	var initErr error
	loggerOnce.Do(func() {
		logger, err := New(cfg)
		if err != nil {
			initErr = err
			return
		}
		SetGlobal(logger)
	})
	return initErr
}

// New creates a new zerolog.Logger with the given configuration
func New(cfg Config) (zerolog.Logger, error) {
	// Set log level
	level, err := zerolog.ParseLevel(strings.ToLower(cfg.Level))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Determine output
	var output io.Writer
	switch strings.ToLower(cfg.Output) {
	case "stdout", "":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		file, err := os.OpenFile(cfg.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return zerolog.Logger{}, err
		}
		output = file
	}

	// Configure format
	if strings.ToLower(cfg.Format) == "console" {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: time.RFC3339,
			NoColor:    false,
		}
	}

	// Build logger
	ctx := zerolog.New(output).With().Timestamp()

	if cfg.EnableCaller {
		ctx = ctx.Caller()
	}

	return ctx.Logger(), nil
}

// SetGlobal sets the global logger instance
func SetGlobal(l zerolog.Logger) {
	loggerMu.Lock()
	defer loggerMu.Unlock()
	globalLogger = l
}

// L returns the global logger instance
func L() *zerolog.Logger {
	loggerMu.RLock()
	defer loggerMu.RUnlock()
	return &globalLogger
}

// Debug logs a debug message
func Debug() *zerolog.Event {
	return L().Debug()
}

// Info logs an info message
func Info() *zerolog.Event {
	return L().Info()
}

// Warn logs a warning message
func Warn() *zerolog.Event {
	return L().Warn()
}

// Error logs an error message
func Error() *zerolog.Event {
	return L().Error()
}

// Fatal logs a fatal message and exits (use sparingly, prefer returning errors)
func Fatal() *zerolog.Event {
	return L().Fatal()
}

// With returns a logger with the given fields
func With() zerolog.Context {
	return L().With()
}

// WithComponent returns a logger with a component field
func WithComponent(component string) zerolog.Logger {
	return L().With().Str("component", component).Logger()
}

// WithPeer returns a logger with a peer ID field
func WithPeer(peerID string) zerolog.Logger {
	return L().With().Str("peer_id", peerID).Logger()
}

// WithCID returns a logger with a CID field
func WithCID(cid string) zerolog.Logger {
	return L().With().Str("cid", cid).Logger()
}

// WithError returns a logger with an error field
func WithError(err error) *zerolog.Event {
	return L().Error().Err(err)
}

// Printf implements log.Printf-compatible interface for legacy code migration
func Printf(format string, v ...interface{}) {
	L().Info().Msgf(format, v...)
}

// Println implements log.Println-compatible interface for legacy code migration
func Println(v ...interface{}) {
	L().Info().Msgf("%v", v...)
}
