package handlers

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type SystemMetrics struct {
	UptimeSeconds float64 `json:"uptime_seconds"`
	Load1         float64 `json:"load1"`
	Load5         float64 `json:"load5"`
	Load15        float64 `json:"load15"`
	MemTotal      uint64  `json:"mem_total_bytes"`
	MemUsed       uint64  `json:"mem_used_bytes"`
	MemFree       uint64  `json:"mem_free_bytes"`
	SwapTotal     uint64  `json:"swap_total_bytes"`
	SwapUsed      uint64  `json:"swap_used_bytes"`
	TxBytes       uint64  `json:"tx_bytes"`
	RxBytes       uint64  `json:"rx_bytes"`
	Interface     string  `json:"interface"`
	InterfaceOK   bool    `json:"interface_ok"`
	Timestamp     int64   `json:"timestamp"`       // unix ms
	IntervalSec   int64   `json:"interval_sec"`    // suggested client sampling interval
}

type SystemHandler struct {
	iface string
}

func NewSystemHandler(iface string) *SystemHandler {
	if iface == "" {
		if detected, err := detectPrimaryIface(); err == nil && detected != "" {
			iface = detected
		}
	}
	return &SystemHandler{iface: iface}
}

func (h *SystemHandler) GetMetrics(c *gin.Context) {
	metrics := SystemMetrics{}

	if up, err := readUptime(); err == nil {
		metrics.UptimeSeconds = up
	}

	if l1, l5, l15, err := readLoadAvg(); err == nil {
		metrics.Load1 = l1
		metrics.Load5 = l5
		metrics.Load15 = l15
	}

	memTotal, memFree, memAvail, swapTotal, swapFree := readMemInfo()
	metrics.MemTotal = memTotal
	if memAvail > 0 {
		metrics.MemUsed = memTotal - memAvail
		metrics.MemFree = memAvail
	} else {
		metrics.MemUsed = memTotal - memFree
		metrics.MemFree = memFree
	}
	metrics.SwapTotal = swapTotal
	if swapTotal > 0 {
		metrics.SwapUsed = swapTotal - swapFree
	}

	iface := h.iface
	metrics.Interface = iface
	metrics.IntervalSec = 5

	if tx, rx, err := readNetDevBytes(iface); err == nil {
		metrics.TxBytes = tx
		metrics.RxBytes = rx
		metrics.InterfaceOK = true
	} else {
		metrics.InterfaceOK = false
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": fmt.Sprintf("failed to read iface %s: %v", iface, err)})
		return
	}

	metrics.Timestamp = time.Now().UnixMilli()

	c.JSON(200, metrics)
}

func readUptime() (float64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, fmt.Errorf("invalid uptime format")
	}
	return strconv.ParseFloat(fields[0], 64)
}

func readLoadAvg() (float64, float64, float64, error) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, err
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, fmt.Errorf("invalid loadavg format")
	}
	l1, _ := strconv.ParseFloat(fields[0], 64)
	l5, _ := strconv.ParseFloat(fields[1], 64)
	l15, _ := strconv.ParseFloat(fields[2], 64)
	return l1, l5, l15, nil
}

func readMemInfo() (memTotal, memFree, memAvailable, swapTotal, swapFree uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		val, _ := strconv.ParseUint(fields[1], 10, 64) // kB
		valBytes := val * 1024
		switch key {
		case "MemTotal":
			memTotal = valBytes
		case "MemFree":
			memFree = valBytes
		case "MemAvailable":
			memAvailable = valBytes
		case "SwapTotal":
			swapTotal = valBytes
		case "SwapFree":
			swapFree = valBytes
		}
	}
	return
}

func readNetDevBytes(iface string) (tx uint64, rx uint64, err error) {
	if iface == "" {
		return 0, 0, fmt.Errorf("interface not set")
	}
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return 0, 0, err
	}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, iface+":") {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		fields := strings.Fields(parts[1])
		if len(fields) < 16 {
			continue
		}
		rx, _ = strconv.ParseUint(fields[0], 10, 64)
		tx, _ = strconv.ParseUint(fields[8], 10, 64)
		return tx, rx, nil
	}
	return 0, 0, fmt.Errorf("iface %s not found in /proc/net/dev", iface)
}

func detectPrimaryIface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "lo") {
			continue
		}
		return iface.Name, nil
	}
	return "", fmt.Errorf("no suitable interface found")
}


