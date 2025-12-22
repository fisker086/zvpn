package policy

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// HookLogger handles logging for policy hooks
type HookLogger struct {
	logFile   *os.File
	logPath   string
	lock      sync.Mutex
	enabled   bool
}

var globalHookLogger *HookLogger
var loggerOnce sync.Once

// GetHookLogger returns the global hook logger instance
func GetHookLogger() *HookLogger {
	loggerOnce.Do(func() {
		globalHookLogger = &HookLogger{
			enabled: true,
		}
		// Default log path: ./logs/hook_policy.log
		globalHookLogger.SetLogPath("./logs/hook_policy.log")
	})
	return globalHookLogger
}

// SetLogPath sets the log file path
func (hl *HookLogger) SetLogPath(path string) error {
	hl.lock.Lock()
	defer hl.lock.Unlock()

	// Close existing file if open
	if hl.logFile != nil {
		hl.logFile.Close()
	}

	// Create directory if needed
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Open log file in append mode
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	hl.logFile = file
	hl.logPath = path
	return nil
}

// LogPacket logs a packet match event
func (hl *HookLogger) LogPacket(hookName string, ctx *Context, action Action) {
	if !hl.enabled {
		return
	}

	hl.lock.Lock()
	defer hl.lock.Unlock()

	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	logMsg := fmt.Sprintf("[%s] Hook: %s, Action: %s, UserID: %d, Src: %s, Dst: %s, Protocol: %s, SrcPort: %d, DstPort: %d\n",
		timestamp, hookName, action.String(), ctx.UserID, ctx.SrcIP, ctx.DstIP, ctx.Protocol, ctx.SrcPort, ctx.DstPort)

	// Write to file if available
	if hl.logFile != nil {
		hl.logFile.WriteString(logMsg)
		hl.logFile.Sync() // Ensure immediate write
	}

	// Also log to standard logger
	log.Printf("HookPolicy: %s", logMsg)
}

// Close closes the log file
func (hl *HookLogger) Close() error {
	hl.lock.Lock()
	defer hl.lock.Unlock()

	if hl.logFile != nil {
		return hl.logFile.Close()
	}
	return nil
}

// Enable enables logging
func (hl *HookLogger) Enable() {
	hl.lock.Lock()
	defer hl.lock.Unlock()
	hl.enabled = true
}

// Disable disables logging
func (hl *HookLogger) Disable() {
	hl.lock.Lock()
	defer hl.lock.Unlock()
	hl.enabled = false
}

