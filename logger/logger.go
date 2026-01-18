package logger

import (
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

var (
	debugEnabled bool
	logFile      *os.File
	logger       *log.Logger
	mu           sync.Mutex
)

// Init initializes the logger with optional debug mode
func Init(debug bool) error {
	mu.Lock()
	defer mu.Unlock()

	debugEnabled = debug

	if debug {
		// Create log file with timestamp
		timestamp := time.Now().Format("2006-01-02_15-04-05")
		filename := fmt.Sprintf("debug_%s.log", timestamp)

		var err error
		logFile, err = os.Create(filename)
		if err != nil {
			return fmt.Errorf("failed to create log file: %w", err)
		}

		logger = log.New(logFile, "", log.Ltime|log.Lmicroseconds)
		logger.Println("=== Debug logging started ===")
		fmt.Printf("Debug logging enabled: %s\n", filename)
	}

	return nil
}

// Close closes the log file
func Close() {
	mu.Lock()
	defer mu.Unlock()

	if logFile != nil {
		logger.Println("=== Debug logging ended ===")
		logFile.Close()
		logFile = nil
	}
}

// Debug logs a debug message if debug mode is enabled
func Debug(format string, args ...interface{}) {
	if !debugEnabled || logger == nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	logger.Printf("[DEBUG] "+format, args...)
}

// Info logs an info message if debug mode is enabled
func Info(format string, args ...interface{}) {
	if !debugEnabled || logger == nil {
		return
	}

	mu.Lock()
	defer mu.Unlock()

	logger.Printf("[INFO] "+format, args...)
}

// IsDebugEnabled returns whether debug mode is enabled
func IsDebugEnabled() bool {
	return debugEnabled
}
