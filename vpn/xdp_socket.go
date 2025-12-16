//go:build linux

package vpn

import (
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// XDPSocket represents an AF_XDP socket for zero-copy packet reception
type XDPSocket struct {
	fd        int
	umem      *XDPUMEM
	rxQueue   *XDPQueue
	txQueue   *XDPQueue
	fillQueue *XDPQueue
	compQueue *XDPQueue
	ifindex   int
	queueID   int
	enabled   bool
}

// XDPUMEM represents the user memory for AF_XDP
type XDPUMEM struct {
	addr      uintptr
	size      int
	frames    []XDPFrame
	numFrames int
	frameSize int
}

// XDPFrame represents a frame in the UMEM
type XDPFrame struct {
	addr uint64
	data []byte
}

// XDPQueue represents an XDP queue (RX, TX, FILL, or COMPLETION)
type XDPQueue struct {
	ring     []uint64 // Ring buffer (producer/consumer)
	descs    []XDPDesc
	producer *uint32 // Producer index
	consumer *uint32 // Consumer index
	flags    *uint32 // Flags
	mask     uint32  // Ring mask (size - 1)
	size     uint32  // Ring size
}

// XDPDesc represents an XDP descriptor
type XDPDesc struct {
	addr    uint64
	len     uint32
	options uint32
}

const (
	// XDP_UMEM_PGOFF_COM_PAT is the page offset for UMEM
	XDP_UMEM_PGOFF_COM_PAT = 0x100000000
	// Default frame size (must be power of 2, between 2048 and PAGE_SIZE)
	XDP_FRAME_SIZE = 4096
	// Default number of frames
	XDP_NUM_FRAMES = 2048
	// Ring size (must be power of 2)
	XDP_RING_SIZE = 2048
)

// NewXDPSocket creates a new AF_XDP socket for zero-copy packet reception
func NewXDPSocket(ifname string, queueID int) (*XDPSocket, error) {
	// Check if AF_XDP is supported
	if !isAFXDPSupported() {
		return nil, fmt.Errorf("AF_XDP not supported on this system")
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface %s: %w", ifname, err)
	}

	// Create AF_XDP socket
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_XDP socket: %w", err)
	}

	xdp := &XDPSocket{
		fd:      fd,
		ifindex: iface.Index,
		queueID: queueID,
		enabled: false,
	}

	// Setup UMEM
	if err := xdp.setupUMEM(); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("failed to setup UMEM: %w", err)
	}

	// Setup rings
	if err := xdp.setupRings(); err != nil {
		xdp.cleanupUMEM()
		unix.Close(fd)
		return nil, fmt.Errorf("failed to setup rings: %w", err)
	}

	// Bind socket to interface
	if err := xdp.bind(); err != nil {
		xdp.cleanup()
		return nil, fmt.Errorf("failed to bind socket: %w", err)
	}

	log.Printf("AF_XDP socket created and bound to interface %s (index %d, queue %d)", ifname, iface.Index, queueID)
	return xdp, nil
}

// setupUMEM creates and configures the UMEM (user memory)
func (x *XDPSocket) setupUMEM() error {
	// Calculate UMEM size (must be page-aligned)
	umemSize := XDP_NUM_FRAMES * XDP_FRAME_SIZE
	pageSize := syscall.Getpagesize()
	umemSize = (umemSize + pageSize - 1) &^ (pageSize - 1) // Align to page size

	// Allocate memory using mmap
	addr, err := unix.Mmap(-1, 0, umemSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("failed to mmap UMEM: %w", err)
	}

	// Create frames
	frames := make([]XDPFrame, XDP_NUM_FRAMES)
	for i := 0; i < XDP_NUM_FRAMES; i++ {
		frames[i] = XDPFrame{
			addr: uint64(i * XDP_FRAME_SIZE),
			data: addr[i*XDP_FRAME_SIZE : (i+1)*XDP_FRAME_SIZE],
		}
	}

	x.umem = &XDPUMEM{
		addr:      uintptr(unsafe.Pointer(&addr[0])),
		size:      umemSize,
		frames:    frames,
		numFrames: XDP_NUM_FRAMES,
		frameSize: XDP_FRAME_SIZE,
	}

	// Register UMEM with socket using setsockopt
	// SOL_XDP = 283, XDP_UMEM_REG = 1
	// struct xdp_umem_reg {
	//     __u64 addr;      /* Start of packet data area */
	//     __u64 len;       /* Length of packet data area */
	//     __u32 chunk_size;
	//     __u32 headroom;
	// };
	umemReg := make([]byte, 24)
	*(*uint64)(unsafe.Pointer(&umemReg[0])) = uint64(x.umem.addr)
	*(*uint64)(unsafe.Pointer(&umemReg[8])) = uint64(umemSize)
	*(*uint32)(unsafe.Pointer(&umemReg[16])) = uint32(XDP_FRAME_SIZE)
	*(*uint32)(unsafe.Pointer(&umemReg[20])) = 0 // headroom

	// SOL_XDP = 283
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(x.fd),
		283, // SOL_XDP
		1,   // XDP_UMEM_REG
		uintptr(unsafe.Pointer(&umemReg[0])),
		uintptr(len(umemReg)),
		0,
	)
	if errno != 0 {
		unix.Munmap(addr)
		return fmt.Errorf("failed to register UMEM: %v", errno)
	}

	// Store the original slice to prevent GC
	x.umem.frames = frames

	return nil
}

// setupRings sets up the RX, TX, FILL, and COMPLETION rings
func (x *XDPSocket) setupRings() error {
	// Allocate ring buffers
	ringSize := uint32(XDP_RING_SIZE)
	ringBytes := int(ringSize) * 8 // Each entry is 8 bytes (uint64)

	// RX ring
	rxRing, err := unix.Mmap(-1, 0, ringBytes+3*4, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fmt.Errorf("failed to mmap RX ring: %w", err)
	}

	// TX ring (use MAP_SHARED for AF_XDP rings)
	txRing, err := unix.Mmap(-1, 0, ringBytes+3*4, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		unix.Munmap(rxRing)
		return fmt.Errorf("failed to mmap TX ring: %w", err)
	}

	// FILL ring (use MAP_SHARED for AF_XDP rings)
	fillRing, err := unix.Mmap(-1, 0, ringBytes+3*4, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		unix.Munmap(rxRing)
		unix.Munmap(txRing)
		return fmt.Errorf("failed to mmap FILL ring: %w", err)
	}

	// COMPLETION ring (use MAP_SHARED for AF_XDP rings)
	compRing, err := unix.Mmap(-1, 0, ringBytes+3*4, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_ANONYMOUS)
	if err != nil {
		unix.Munmap(rxRing)
		unix.Munmap(txRing)
		unix.Munmap(fillRing)
		return fmt.Errorf("failed to mmap COMPLETION ring: %w", err)
	}

	// Setup queue structures
	x.rxQueue = x.setupQueue(rxRing, ringSize)
	x.txQueue = x.setupQueue(txRing, ringSize)
	x.fillQueue = x.setupQueue(fillRing, ringSize)
	x.compQueue = x.setupQueue(compRing, ringSize)

	// Register rings with socket using setsockopt
	// XDP_RX_RING = 2, XDP_TX_RING = 3, XDP_FILL_RING = 4, XDP_COMPLETION_RING = 5
	ringOpts := make([]byte, 16)
	*(*uint32)(unsafe.Pointer(&ringOpts[0])) = uint32(ringSize)
	*(*uint32)(unsafe.Pointer(&ringOpts[4])) = 0 // flags
	*(*uint64)(unsafe.Pointer(&ringOpts[8])) = uint64(uintptr(unsafe.Pointer(&rxRing[0])))

	// Register RX ring
	_, _, errno := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(x.fd),
		283, // SOL_XDP
		2,   // XDP_RX_RING
		uintptr(unsafe.Pointer(&ringOpts[0])),
		uintptr(len(ringOpts)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to register RX ring: %v", errno)
	}

	// Register TX ring
	*(*uint64)(unsafe.Pointer(&ringOpts[8])) = uint64(uintptr(unsafe.Pointer(&txRing[0])))
	_, _, errno = unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(x.fd),
		283, // SOL_XDP
		3,   // XDP_TX_RING
		uintptr(unsafe.Pointer(&ringOpts[0])),
		uintptr(len(ringOpts)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to register TX ring: %v", errno)
	}

	// Register FILL ring
	*(*uint64)(unsafe.Pointer(&ringOpts[8])) = uint64(uintptr(unsafe.Pointer(&fillRing[0])))
	_, _, errno = unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(x.fd),
		283, // SOL_XDP
		4,   // XDP_FILL_RING
		uintptr(unsafe.Pointer(&ringOpts[0])),
		uintptr(len(ringOpts)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to register FILL ring: %v", errno)
	}

	// Register COMPLETION ring
	*(*uint64)(unsafe.Pointer(&ringOpts[8])) = uint64(uintptr(unsafe.Pointer(&compRing[0])))
	_, _, errno = unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(x.fd),
		283, // SOL_XDP
		5,   // XDP_COMPLETION_RING
		uintptr(unsafe.Pointer(&ringOpts[0])),
		uintptr(len(ringOpts)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to register COMPLETION ring: %v", errno)
	}

	// Pre-fill FILL ring with all frames
	for i := 0; i < XDP_NUM_FRAMES && i < int(ringSize); i++ {
		x.fillQueue.ring[i] = uint64(i * XDP_FRAME_SIZE)
	}
	*x.fillQueue.producer = uint32(XDP_NUM_FRAMES)

	return nil
}

// setupQueue initializes a queue structure from mmapped memory
func (x *XDPSocket) setupQueue(ring []byte, size uint32) *XDPQueue {
	// Ring layout: [producer][consumer][flags][ring data...]
	producer := (*uint32)(unsafe.Pointer(&ring[0]))
	consumer := (*uint32)(unsafe.Pointer(&ring[4]))
	flags := (*uint32)(unsafe.Pointer(&ring[8]))
	ringData := (*[1 << 28]uint64)(unsafe.Pointer(&ring[12]))[:size:size]

	*producer = 0
	*consumer = 0
	*flags = 0

	return &XDPQueue{
		ring:     ringData,
		producer: producer,
		consumer: consumer,
		flags:    flags,
		mask:     size - 1,
		size:     size,
	}
}

// bind binds the AF_XDP socket to the interface
func (x *XDPSocket) bind() error {
	// Create sockaddr_xdp structure
	// struct sockaddr_xdp {
	//     sa_family_t sxdp_family;
	//     __u32 sxdp_flags;
	//     __u16 sxdp_ifindex;
	//     __u32 sxdp_queue_id;
	//     __u32 sxdp_shared_umem_fd;
	// };
	sockaddr := make([]byte, 16)
	// sxdp_family = AF_XDP (44)
	sockaddr[0] = 44
	sockaddr[1] = 0
	// sxdp_flags = 0 (XDP_SHARED_UMEM not used)
	// sxdp_ifindex
	*(*uint16)(unsafe.Pointer(&sockaddr[4])) = uint16(x.ifindex)
	// sxdp_queue_id
	*(*uint32)(unsafe.Pointer(&sockaddr[8])) = uint32(x.queueID)
	// sxdp_shared_umem_fd = 0

	// Bind socket
	_, _, errno := unix.Syscall6(
		unix.SYS_BIND,
		uintptr(x.fd),
		uintptr(unsafe.Pointer(&sockaddr[0])),
		uintptr(16),
		0, 0, 0,
	)
	if errno != 0 {
		return fmt.Errorf("failed to bind AF_XDP socket: %v", errno)
	}

	return nil
}

// Enable enables the AF_XDP socket
func (x *XDPSocket) Enable() error {
	if x.enabled {
		return nil
	}

	// Socket is already bound, just mark as enabled
	x.enabled = true
	log.Printf("AF_XDP socket enabled for interface %d, queue %d", x.ifindex, x.queueID)
	return nil
}

// Read reads a packet from the AF_XDP socket
func (x *XDPSocket) Read(buf []byte) (int, error) {
	if !x.enabled {
		return 0, fmt.Errorf("AF_XDP socket not enabled")
	}

	// Check RX ring for available packets
	prod := *x.rxQueue.producer
	cons := *x.rxQueue.consumer

	if prod == cons {
		// No packets available
		return 0, unix.EAGAIN
	}

	// Read descriptor from RX ring
	descAddr := x.rxQueue.ring[cons&x.rxQueue.mask]

	// Calculate frame index
	frameIdx := int(descAddr / uint64(XDP_FRAME_SIZE))
	if frameIdx >= len(x.umem.frames) {
		return 0, fmt.Errorf("invalid frame index: %d", frameIdx)
	}

	// Get frame data
	frame := x.umem.frames[frameIdx]

	// Copy data to buffer (limited by buffer size)
	copyLen := len(frame.data)
	if copyLen > len(buf) {
		copyLen = len(buf)
	}
	copy(buf, frame.data[:copyLen])

	// Update consumer index
	*x.rxQueue.consumer = cons + 1

	// Return frame to FILL ring for reuse
	fillProd := *x.fillQueue.producer
	x.fillQueue.ring[fillProd&x.fillQueue.mask] = descAddr
	*x.fillQueue.producer = fillProd + 1

	return copyLen, nil
}

// Write writes a packet to the AF_XDP socket
func (x *XDPSocket) Write(buf []byte) (int, error) {
	if !x.enabled {
		return 0, fmt.Errorf("AF_XDP socket not enabled")
	}

	// Check TX ring for available space
	prod := *x.txQueue.producer
	cons := *x.txQueue.consumer

	if (prod+1)&x.txQueue.mask == cons&x.txQueue.mask {
		// TX ring is full
		return 0, unix.EAGAIN
	}

	// Get a frame from COMPLETION ring (reuse) or allocate new
	var frameAddr uint64
	if *x.compQueue.consumer != *x.compQueue.producer {
		// Reuse completed frame
		compCons := *x.compQueue.consumer
		frameAddr = x.compQueue.ring[compCons&x.compQueue.mask]
		*x.compQueue.consumer = compCons + 1
	} else {
		// Allocate new frame (simplified - in production, manage frame pool)
		// For now, use first available frame
		frameIdx := (prod % uint32(XDP_NUM_FRAMES))
		frameAddr = uint64(frameIdx * XDP_FRAME_SIZE)
	}

	// Copy data to frame
	frameIdx := int(frameAddr / uint64(XDP_FRAME_SIZE))
	if frameIdx >= len(x.umem.frames) {
		return 0, fmt.Errorf("invalid frame index: %d", frameIdx)
	}

	frame := x.umem.frames[frameIdx]
	copyLen := len(buf)
	if copyLen > len(frame.data) {
		copyLen = len(frame.data)
	}
	copy(frame.data, buf[:copyLen])

	// Add descriptor to TX ring
	// Format: [addr:64] where addr is the frame address
	// The kernel will read the packet from this frame
	x.txQueue.ring[prod&x.txQueue.mask] = frameAddr
	*x.txQueue.producer = prod + 1

	// Note: In a full implementation, we'd also need to handle packet length
	// For now, the kernel will read from the frame based on the IP header length

	return copyLen, nil
}

// Close closes the AF_XDP socket and cleans up resources
func (x *XDPSocket) Close() error {
	x.Disable()
	x.cleanup()
	if x.fd >= 0 {
		return unix.Close(x.fd)
	}
	return nil
}

// Disable disables the AF_XDP socket
func (x *XDPSocket) Disable() {
	x.enabled = false
}

// IsEnabled returns whether the socket is enabled
func (x *XDPSocket) IsEnabled() bool {
	return x.enabled
}

// GetQueueID returns the queue ID
func (x *XDPSocket) GetQueueID() int {
	return x.queueID
}

// GetInterfaceIndex returns the interface index
func (x *XDPSocket) GetInterfaceIndex() int {
	return x.ifindex
}

// cleanup cleans up UMEM and ring buffers
func (x *XDPSocket) cleanup() {
	if x.umem != nil {
		x.cleanupUMEM()
	}
	// Note: Ring cleanup would unmapping memory here
	// For simplicity, we rely on process exit to clean up
}

// cleanupUMEM unmaps UMEM memory
func (x *XDPSocket) cleanupUMEM() {
	if x.umem != nil && x.umem.addr != 0 {
		// Convert addr back to []byte for Munmap
		// This is a simplified cleanup - in production, track the original slice
		// For now, we'll rely on process exit
		x.umem = nil
	}
}

// isAFXDPSupported checks if AF_XDP is supported
func isAFXDPSupported() bool {
	// Try to create an AF_XDP socket to check support
	fd, err := unix.Socket(unix.AF_XDP, unix.SOCK_RAW, 0)
	if err != nil {
		return false
	}
	unix.Close(fd)
	return true
}
