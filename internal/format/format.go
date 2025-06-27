package format

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
)

type Version uint8

func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

const (
	VersionUnknown     Version = 0
	VersionV1          Version = 1
	magicNumber                = "HGVF"
	magicNumberLen             = len(magicNumber)
	versionLen                 = 1
	saltLen                    = 16
	nonceLen                   = 24
	kdfMemoryLen               = 4
	kdfIterationsLen           = 4
	kdfThreadsLen              = 1
	kdfLen                     = kdfMemoryLen + kdfIterationsLen + kdfThreadsLen
	totalFileLengthLen         = 2
	hmacLen                    = sha256.Size
	TotalHeaderLen             = magicNumberLen + versionLen + saltLen + nonceLen + kdfLen + totalFileLengthLen + hmacLen
	MaxCipherTextSize          = math.MaxUint16
)

const ()

type Header struct {
	MagicNumber            [magicNumberLen]byte
	Version                Version
	CipherTextKeySalt      [saltLen]byte
	CipherTextKeyNonce     [nonceLen]byte
	CipherTextKeyKDFParams [kdfLen]byte
	TotalPayloadLength     uint16
	HMAC                   [hmacLen]byte
}

func Parse(input io.Reader) (*Header, io.Reader, error) {
	if input == nil {
		return nil, nil, errors.New("input reader cannot be nil")
	}

	var header Header
	r := bufio.NewReader(input)

	headerBuf := make([]byte, TotalHeaderLen)
	if n, err := io.ReadFull(r, headerBuf); err != nil {
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, fmt.Errorf("incomplete header, expected %d bytes, read %d: %w", TotalHeaderLen, n, err)
		}

		return nil, nil, fmt.Errorf("failed to read header, expected %d bytes: %w, ", TotalHeaderLen, err)
	}

	offset := 0

	copy(header.MagicNumber[:], headerBuf[offset:offset+magicNumberLen])
	offset += magicNumberLen
	if !bytes.Equal(header.MagicNumber[:], []byte(magicNumber)) {
		return nil, nil, fmt.Errorf("invalid magic number: expected %q, got %q", magicNumber, header.MagicNumber)
	}

	header.Version = Version(headerBuf[offset])
	offset += versionLen
	if header.Version != VersionV1 {
		return nil, nil, fmt.Errorf("invalid version: expected version %s, got %s", VersionV1, header.Version)
	}

	copy(header.CipherTextKeySalt[:], headerBuf[offset:offset+saltLen])
	offset += saltLen

	copy(header.CipherTextKeyNonce[:], headerBuf[offset:offset+nonceLen])
	offset += nonceLen

	copy(header.CipherTextKeyKDFParams[:], headerBuf[offset:offset+kdfLen])
	offset += kdfLen

	header.TotalPayloadLength = binary.BigEndian.Uint16(headerBuf[offset : offset+totalFileLengthLen])
	offset += totalFileLengthLen

	copy(header.HMAC[:], headerBuf[offset:offset+hmacLen])

	if r == input {
		return &header, r, nil
	}

	// Otherwise, unwind the bufio overread and return the unbuffered input.
	buf, err := r.Peek(r.Buffered())
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: %w", err)
	}

	payload := io.MultiReader(bytes.NewReader(buf), input)
	return &header, payload, nil
}

func Encode(output io.Writer, mac hash.Hash, salt [saltLen]byte, nonce [nonceLen]byte, kdfParams KDFParams, cipherTextLen uint16) error {
	w := io.MultiWriter(output, mac)

	if _, err := w.Write([]byte(magicNumber)); err != nil {
		return fmt.Errorf("failed to write magic number: %w", err)
	}

	if _, err := w.Write([]byte{byte(VersionV1)}); err != nil {
		return fmt.Errorf("failed to write version: %w", err)
	}

	if _, err := w.Write(salt[:]); err != nil {
		return fmt.Errorf("failed to write salt: %w", err)
	}

	if _, err := w.Write(nonce[:]); err != nil {
		return fmt.Errorf("failed to write nonce: %w", err)
	}

	kdfParamsBytes, err := EncodeKDFParams(&kdfParams)
	if err != nil {
		return fmt.Errorf("failed to encode kdf params: %w", err)
	}

	if _, err := w.Write(kdfParamsBytes[:]); err != nil {
		return fmt.Errorf("failed to write kdf params: %w", err)
	}

	totalPayloadLength := uint16(TotalHeaderLen) + cipherTextLen
	if err := binary.Write(w, binary.BigEndian, totalPayloadLength); err != nil {
		return fmt.Errorf("failed to write total payload length: %w", err)
	}

	if _, err := w.Write(mac.Sum(nil)); err != nil {
		return fmt.Errorf("failed to write hmac: %w", err)
	}

	return nil
}

func ComputeMAC(header *Header, mac hash.Hash) ([]byte, error) {
	if _, err := mac.Write(header.MagicNumber[:]); err != nil {
		return nil, fmt.Errorf("failed to write magic to HMAC: %w", err)
	}
	if _, err := mac.Write([]byte{byte(header.Version)}); err != nil {
		return nil, fmt.Errorf("failed to write version to HMAC: %w", err)
	}
	if _, err := mac.Write(header.CipherTextKeySalt[:]); err != nil {
		return nil, fmt.Errorf("failed to write salt to HMAC: %w", err)
	}
	if _, err := mac.Write(header.CipherTextKeyNonce[:]); err != nil {
		return nil, fmt.Errorf("failed to write nonce to HMAC: %w", err)
	}
	if _, err := mac.Write(header.CipherTextKeyKDFParams[:]); err != nil {
		return nil, fmt.Errorf("failed to write KDF params to HMAC: %w", err)
	}
	if err := binary.Write(mac, binary.BigEndian, header.TotalPayloadLength); err != nil {
		return nil, fmt.Errorf("failed to write total file length to HMAC: %w", err)
	}

	return mac.Sum(nil), nil
}

func ValidateMAC(header *Header, mac hash.Hash) error {
	computedHMAC, err := ComputeMAC(header, mac)
	if err != nil {
		return err
	}

	if subtle.ConstantTimeCompare(computedHMAC, header.HMAC[:]) != 1 {
		return errors.New("invalid HMAC")
	}

	return nil
}
