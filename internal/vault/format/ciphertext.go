package format

import (
	"errors"
	"fmt"
	"io"
)

// ReadCipherText ...
// ReadCipherText returns an error if the cipher text is not the expected size
func ReadCipherText(r io.Reader, header *Header) ([]byte, error) {
	if header.TotalPayloadLength < uint16(TotalHeaderLen) {
		return nil, fmt.Errorf("total payload length %d is smaller than header length %d", header.TotalPayloadLength, TotalHeaderLen)
	}

	cipherTextLen := header.TotalPayloadLength - uint16(TotalHeaderLen)
	cipherText := make([]byte, cipherTextLen)

	if n, err := io.ReadFull(r, cipherText); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("file truncated: expected %d bytes, read %d: %w", cipherTextLen, n, err)
		}

		return nil, fmt.Errorf("failed to read ciphertext: %w", err)
	}

	return cipherText, nil
}
