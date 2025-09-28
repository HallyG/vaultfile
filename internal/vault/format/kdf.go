package format

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// KDFParams represents Argon2id parameters
type KDFParams struct {
	MemoryKiB     uint32
	NumIterations uint32
	NumThreads    uint8
}

func parseKDFParams(bytes [kdfLen]byte) (*KDFParams, error) {
	return &KDFParams{
		MemoryKiB:     binary.BigEndian.Uint32(bytes[0:4]),
		NumIterations: binary.BigEndian.Uint32(bytes[4:8]),
		NumThreads:    uint8(bytes[8]),
	}, nil
}

func encodeKDFParams(params *KDFParams) ([kdfLen]byte, error) {
	var result [kdfLen]byte
	buf := bytes.NewBuffer(nil)

	if err := binary.Write(buf, binary.BigEndian, params.MemoryKiB); err != nil {
		return result, fmt.Errorf("failed to write KDF memory parameter: %w", err)
	}

	if err := binary.Write(buf, binary.BigEndian, params.NumIterations); err != nil {
		return result, fmt.Errorf("failed to write KDF iterations parameter: %w", err)
	}

	if _, err := buf.Write([]byte{params.NumThreads}); err != nil {
		return result, fmt.Errorf("failed to write KDF threads parameter: %w", err)
	}

	copy(result[:], buf.Bytes())
	return result, nil
}
