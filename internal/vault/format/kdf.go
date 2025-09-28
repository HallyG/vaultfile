package format

import (
	"encoding/binary"
	"fmt"
)

const (
	memoryKiBSize     = 4
	numIterationsSize = 4
	numThreadsSize    = 1
	KDFParamsLen      = memoryKiBSize + numIterationsSize + numThreadsSize
)

// KDFParams represents Argon2id parameters
type KDFParams struct {
	MemoryKiB     uint32
	NumIterations uint32
	NumThreads    uint8
}

// MarshalBinary implements [encoding.BinaryMarshaler].
func (p *KDFParams) MarshalBinary() ([]byte, error) {
	var result [KDFParamsLen]byte
	binary.BigEndian.PutUint32(result[0:4], p.MemoryKiB)
	binary.BigEndian.PutUint32(result[4:8], p.NumIterations)
	result[8] = p.NumThreads
	return result[:], nil
}

// UnmarshalBinary implements [encoding.BinaryUnmarshaler].
func (p *KDFParams) UnmarshalBinary(data []byte) error {
	if len(data) != KDFParamsLen {
		return fmt.Errorf("invalid length: got %d, expected %d", len(data), KDFParamsLen)
	}

	p.MemoryKiB = binary.BigEndian.Uint32(data[0:4])
	p.NumIterations = binary.BigEndian.Uint32(data[4:8])
	p.NumThreads = data[8]

	return nil
}
