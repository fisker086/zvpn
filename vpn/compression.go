package vpn

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"sync"

	"github.com/pierrec/lz4/v4"
)

// CompressionType 压缩类型
type CompressionType string

const (
	CompressionNone CompressionType = "none"
	CompressionLZ4  CompressionType = "lz4"
	CompressionGzip  CompressionType = "gzip"
)

// Compressor 压缩器接口
type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

// LZ4Compressor LZ4压缩器
type LZ4Compressor struct {
	writer *lz4.Writer
	reader *lz4.Reader
	pool   *sync.Pool
}

// NewLZ4Compressor 创建LZ4压缩器
func NewLZ4Compressor() *LZ4Compressor {
	return &LZ4Compressor{
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// Compress 压缩数据
func (c *LZ4Compressor) Compress(data []byte) ([]byte, error) {
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()

	writer := lz4.NewWriter(buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// Decompress 解压数据
func (c *LZ4Compressor) Decompress(data []byte) ([]byte, error) {
	reader := lz4.NewReader(bytes.NewReader(data))
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()

	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// GzipCompressor Gzip压缩器
type GzipCompressor struct {
	pool *sync.Pool
}

// NewGzipCompressor 创建Gzip压缩器
func NewGzipCompressor() *GzipCompressor {
	return &GzipCompressor{
		pool: &sync.Pool{
			New: func() interface{} {
				return &bytes.Buffer{}
			},
		},
	}
}

// Compress 压缩数据
func (c *GzipCompressor) Compress(data []byte) ([]byte, error) {
	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()

	writer := gzip.NewWriter(buf)
	if _, err := writer.Write(data); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// Decompress 解压数据
func (c *GzipCompressor) Decompress(data []byte) ([]byte, error) {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	buf := c.pool.Get().(*bytes.Buffer)
	defer c.pool.Put(buf)
	buf.Reset()

	if _, err := io.Copy(buf, reader); err != nil {
		return nil, err
	}

	result := make([]byte, buf.Len())
	copy(result, buf.Bytes())
	return result, nil
}

// CompressionManager 压缩管理器
type CompressionManager struct {
	compressors map[CompressionType]Compressor
	defaultType CompressionType
}

// NewCompressionManager 创建压缩管理器
func NewCompressionManager(defaultType CompressionType) *CompressionManager {
	cm := &CompressionManager{
		compressors: make(map[CompressionType]Compressor),
		defaultType: defaultType,
	}

	// 注册压缩器
	if defaultType == CompressionLZ4 || defaultType == "" {
		cm.compressors[CompressionLZ4] = NewLZ4Compressor()
	}
	if defaultType == CompressionGzip || defaultType == "" {
		cm.compressors[CompressionGzip] = NewGzipCompressor()
	}

	return cm
}

// Compress 压缩数据
func (cm *CompressionManager) Compress(data []byte, compType CompressionType) ([]byte, error) {
	if compType == CompressionNone || compType == "" {
		return data, nil
	}

	compressor, ok := cm.compressors[compType]
	if !ok {
		return nil, fmt.Errorf("unsupported compression type: %s", compType)
	}

	return compressor.Compress(data)
}

// Decompress 解压数据
// 如果解压失败，返回原始数据（可能数据未压缩）
func (cm *CompressionManager) Decompress(data []byte, compType CompressionType) ([]byte, error) {
	if compType == CompressionNone || compType == "" {
		return data, nil
	}

	compressor, ok := cm.compressors[compType]
	if !ok {
		// 如果压缩类型不支持，返回原始数据
		return data, nil
	}

	// 尝试解压，如果失败可能数据未压缩
	decompressed, err := compressor.Decompress(data)
	if err != nil {
		// 解压失败，可能数据未压缩，返回原始数据
		return data, nil
	}

	return decompressed, nil
}

// GetDefaultType 获取默认压缩类型
func (cm *CompressionManager) GetDefaultType() CompressionType {
	return cm.defaultType
}

