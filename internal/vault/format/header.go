package format

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
)

const (
	MagicNumber           = "HGVF"
	MagicNumberLen        = len(MagicNumber)
	VersionLen            = 1
	SaltLen               = 16
	NonceLen              = 24
	TotalPayloadLengthLen = 2
	HMACLen               = sha256.Size
	TotalHeaderLen        = MagicNumberLen + VersionLen + SaltLen + NonceLen + KDFParamsLen + TotalPayloadLengthLen + HMACLen
	MaxCipherTextSize     = math.MaxUint16
)

// Validate checks if the Header fields are valid.
func (h *Header) Validate() error {
	if !bytes.Equal(h.MagicNumber[:], []byte(MagicNumber)) {
		return fmt.Errorf("magic number: expected %q, got %q", MagicNumber, h.MagicNumber)
	}

	if h.Version != VersionV1 {
		return fmt.Errorf("version: expected %s, got %s", VersionV1, h.Version)
	}

	if h.TotalPayloadLength < uint16(TotalHeaderLen) {
		return fmt.Errorf("total payload length must be at least %d bytes, got %d", h.TotalPayloadLength, TotalHeaderLen)
	}

	return nil
}

// MarshalBinary implements [encoding.BinaryMarshaler].
func (h *Header) MarshalBinary() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, fmt.Errorf("invalid: %w", err)
	}

	buf := make([]byte, TotalHeaderLen)
	offset := 0

	copy(buf[offset:offset+MagicNumberLen], h.MagicNumber[:])
	offset += MagicNumberLen

	buf[offset] = byte(h.Version)
	offset += VersionLen

	copy(buf[offset:offset+SaltLen], h.CipherTextKeySalt[:])
	offset += SaltLen

	copy(buf[offset:offset+NonceLen], h.CipherTextKeyNonce[:])
	offset += NonceLen

	kdfParamsBytes, err := h.CipherTextKeyKDFParams.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal KDF params: %w", err)
	}
	copy(buf[offset:offset+KDFParamsLen], kdfParamsBytes)
	offset += KDFParamsLen

	binary.BigEndian.PutUint16(buf[offset:offset+TotalPayloadLengthLen], h.TotalPayloadLength)
	offset += TotalPayloadLengthLen

	copy(buf[offset:offset+HMACLen], h.HMAC[:])

	return buf, nil
}

// UnmarshalBinary implements [encoding.BinaryMarshaler].
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) != TotalHeaderLen {
		return fmt.Errorf("invalid length: got %d, expected %d", len(data), TotalHeaderLen)
	}

	offset := 0

	copy(h.MagicNumber[:], data[offset:offset+MagicNumberLen])
	offset += MagicNumberLen

	h.Version = Version(data[offset])
	offset += VersionLen

	copy(h.CipherTextKeySalt[:], data[offset:offset+SaltLen])
	offset += SaltLen

	copy(h.CipherTextKeyNonce[:], data[offset:offset+NonceLen])
	offset += NonceLen

	if err := h.CipherTextKeyKDFParams.UnmarshalBinary(data[offset : offset+KDFParamsLen]); err != nil {
		return fmt.Errorf("unmarshal KDF params: %w", err)
	}
	offset += KDFParamsLen

	h.TotalPayloadLength = binary.BigEndian.Uint16(data[offset : offset+TotalPayloadLengthLen])
	offset += TotalPayloadLengthLen

	copy(h.HMAC[:], data[offset:offset+HMACLen])

	if err := h.Validate(); err != nil {
		return fmt.Errorf("invalid: %w", err)
	}

	return nil
}
