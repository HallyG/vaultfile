package format

import (
	"errors"
	"fmt"
	"io"
)

func ReadCipherText(r io.Reader, header *Header) ([]byte, error) {
	if header.TotalPayloadLength < uint16(TotalHeaderLen) {
		return nil, fmt.Errorf("total payload length %d is smaller than header length %d", header.TotalPayloadLength, TotalHeaderLen)
	}

	cipherTextLen := int(header.TotalPayloadLength) - TotalHeaderLen
	if cipherTextLen < 0 {
		cipherTextLen = 0
	}

	cipherText := make([]byte, cipherTextLen)
	if n, err := io.ReadFull(r, cipherText); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("file truncated: expected %d bytes, read %d: %w", cipherTextLen, n, err)
		}

		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	return cipherText, nil
}
