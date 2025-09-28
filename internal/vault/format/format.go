package format

import (
	"errors"
	"fmt"
	"hash"
	"io"
)

type Version uint8

func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

const (
	VersionUnknown Version = 0
	VersionV1      Version = 1
)

type Header struct {
	MagicNumber               [MagicNumberLen]byte
	Version                   Version
	CipherTextKeySalt         [SaltLen]byte
	CipherTextKeyNonce        [NonceLen]byte
	CipherTextKeyKDFParams    KDFParams
	cipherTextKeyKDFParamsRaw [KDFParamsLen]byte
	TotalPayloadLength        uint16
	HMAC                      [HMACLen]byte
}

// ParseHeader parses a Header from an [io.Reader] and returns the header and a reader for the remaining data.
func ParseHeader(input io.Reader) (*Header, io.Reader, error) {
	if input == nil {
		return nil, nil, errors.New("input reader cannot be nil")
	}

	headerBuf := make([]byte, TotalHeaderLen)
	n, err := io.ReadFull(input, headerBuf)
	if err != nil {
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			err = fmt.Errorf("truncated: expected %d bytes, read %d: %w", TotalHeaderLen, n, err)
		}

		return nil, nil, fmt.Errorf("read header: %w", err)
	}

	var header Header
	if err := header.UnmarshalBinary(headerBuf); err != nil {
		return nil, nil, fmt.Errorf("unmarshal header: %w", err)
	}

	/*
			buf, err := r.Peek(r.Buffered())
		if err != nil {
			return nil, nil, fmt.Errorf("internal error: %w", err)
		}

		payload := io.MultiReader(bytes.NewReader(buf), input)
		return &header, payload, nil
	*/

	return &header, input, nil
}

// EncodeHeader encodes a Header to an io.Writer, updating the provided HMAC hash.
func EncodeHeader(output io.Writer, mac hash.Hash, salt [SaltLen]byte, nonce [NonceLen]byte, kdfParams KDFParams, cipherTextLen uint16) error {
	if output == nil {
		return errors.New("output writer cannot be nil")
	}

	if mac == nil {
		return errors.New("HMAC hash cannot be nil")
	}

	var magicNumber [MagicNumberLen]byte
	copy(magicNumber[:], MagicNumber)

	header := Header{
		MagicNumber:            magicNumber,
		Version:                VersionV1,
		CipherTextKeySalt:      salt,
		CipherTextKeyNonce:     nonce,
		CipherTextKeyKDFParams: kdfParams,
		TotalPayloadLength:     uint16(TotalHeaderLen) + cipherTextLen,
	}

	// Marshal header without HMAC
	header.HMAC = [HMACLen]byte{}
	data, err := header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal header: %w", err)
	}

	// Write header data to HMAC hash
	if _, err := mac.Write(data[:len(data)-HMACLen]); err != nil {
		return fmt.Errorf("update HMAC: %w", err)
	}

	// Update HMAC field with computed value
	copy(header.HMAC[:], mac.Sum(nil)[:HMACLen])

	// Re-marshal with correct HMAC
	data, err = header.MarshalBinary()
	if err != nil {
		return fmt.Errorf("marshal header with HMAC: %w", err)
	}

	if _, err := output.Write(data); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	return nil
}

// ReadCipherText returns an error if the cipher text is not the expected size.
func ReadCipherText(r io.Reader, header *Header) ([]byte, error) {
	if header.TotalPayloadLength < uint16(TotalHeaderLen) {
		return nil, fmt.Errorf("total payload length %d is smaller than header length %d", header.TotalPayloadLength, TotalHeaderLen)
	}

	cipherTextLen := header.TotalPayloadLength - uint16(TotalHeaderLen)
	cipherText := make([]byte, cipherTextLen)

	if n, err := io.ReadFull(r, cipherText); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("truncated: expected %d bytes, read %d: %w", cipherTextLen, n, err)
		}

		return nil, fmt.Errorf("read: %w", err)
	}

	return cipherText, nil
}
