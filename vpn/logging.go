package vpn

import (
	"log"
	"sync/atomic"
)

// Log sampling for performance optimization
var (
	// logPacketCounter counts packets for sampling
	logPacketCounter int64

	// logSampleRate controls how often to log (every N packets)
	// Set to 0 to disable sampling (log all)
	logSampleRate int64 = 1000 // Default: log every 1000 packets
)

// SetLogSampleRate sets the log sampling rate
// 0 = log all packets, N = log every N packets
func SetLogSampleRate(rate int64) {
	atomic.StoreInt64(&logSampleRate, rate)
}

// ShouldLogPacket returns true if this packet should be logged (based on sampling)
// Exported for use in other packages
func ShouldLogPacket() bool {
	rate := atomic.LoadInt64(&logSampleRate)
	if rate == 0 {
		return true // Log all
	}
	counter := atomic.AddInt64(&logPacketCounter, 1)
	return counter%rate == 0
}

// LogPacket logs packet information with sampling
func LogPacket(format string, args ...interface{}) {
	if ShouldLogPacket() {
		log.Printf(format, args...)
	}
}

// LogPacketAlways logs packet information without sampling (for errors/important events)
func LogPacketAlways(format string, args ...interface{}) {
	log.Printf(format, args...)
}

