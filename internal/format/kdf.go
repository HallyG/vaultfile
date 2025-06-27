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

func (h *Header) ParseKDFParams() (*KDFParams, error) {
	data := h.CipherTextKeyKDFParams[:]

	if len(data) != kdfLen {
		return nil, fmt.Errorf("invalid KDF parameters length, expected %d bytes, got %d", kdfLen, len(data))
	}

	return &KDFParams{
		MemoryKiB:     binary.BigEndian.Uint32(data[0:4]),
		NumIterations: binary.BigEndian.Uint32(data[4:8]),
		NumThreads:    uint8(data[8]),
	}, nil
}

func EncodeKDFParams(params *KDFParams) ([kdfLen]byte, error) {
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
