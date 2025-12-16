package vpn

import "sync"

// Packet pools for buffer reuse to reduce GC pressure
var (
	// packetPool is used for TUN device reads
	packetPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 4096)
		},
	}

	// cstpPacketPool is used for CSTP packet encapsulation
	// STF(3) + CSTP header(8) + IP packet(1500) + margin
	cstpPacketPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 8192)
		},
	}

	// ipPacketPool is used for IP packet processing
	ipPacketPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, 1500)
		},
	}
)

// GetPacketBuffer gets a buffer from the packet pool
// Caller must call PutPacketBuffer when done
func GetPacketBuffer() []byte {
	return packetPool.Get().([]byte)
}

// PutPacketBuffer returns a buffer to the packet pool
// Important: Reset the slice length before putting back
func PutPacketBuffer(buf []byte) {
	if buf == nil {
		return
	}
	// Reset to full capacity to avoid memory leaks
	buf = buf[:cap(buf)]
	packetPool.Put(buf)
}

// GetCSTPPacketBuffer gets a buffer for CSTP packet encapsulation
func GetCSTPPacketBuffer() []byte {
	return cstpPacketPool.Get().([]byte)
}

// PutCSTPPacketBuffer returns a CSTP buffer to the pool
func PutCSTPPacketBuffer(buf []byte) {
	if buf == nil {
		return
	}
	buf = buf[:cap(buf)]
	cstpPacketPool.Put(buf)
}

// GetIPPacketBuffer gets a buffer for IP packet processing
func GetIPPacketBuffer() []byte {
	return ipPacketPool.Get().([]byte)
}

// PutIPPacketBuffer returns an IP packet buffer to the pool
func PutIPPacketBuffer(buf []byte) {
	if buf == nil {
		return
	}
	buf = buf[:cap(buf)]
	ipPacketPool.Put(buf)
}

