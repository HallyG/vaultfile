package format

import (
	"bufio"
	"bytes"
	"crypto/sha256"
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
	MagicNumber                = "HGVF"
	magicNumberLen             = len(MagicNumber)
	versionLen                 = 1
	SaltLen                    = 16
	NonceLen                   = 24
	kdfMemoryLen               = 4
	kdfIterationsLen           = 4
	kdfThreadsLen              = 1
	kdfLen                     = kdfMemoryLen + kdfIterationsLen + kdfThreadsLen
	totalFileLengthLen         = 2
	hmacLen                    = sha256.Size
	TotalHeaderLen             = magicNumberLen + versionLen + SaltLen + NonceLen + kdfLen + totalFileLengthLen + hmacLen
	MaxCipherTextSize          = math.MaxUint16
)

type Header struct {
	MagicNumber               [magicNumberLen]byte
	Version                   Version
	CipherTextKeySalt         [SaltLen]byte
	CipherTextKeyNonce        [NonceLen]byte
	cipherTextKeyKDFParamsRaw [kdfLen]byte
	CipherTextKeyKDFParams    KDFParams
	TotalPayloadLength        uint16
	HMAC                      [hmacLen]byte
}

func ParseHeader(input io.Reader) (*Header, io.Reader, error) {
	if input == nil {
		return nil, nil, errors.New("input reader cannot be nil")
	}

	var header Header
	r := bufio.NewReader(input)

	headerBuf := make([]byte, TotalHeaderLen)
	if n, err := io.ReadFull(r, headerBuf); err != nil {
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, nil, fmt.Errorf("truncated header, expected %d bytes, read %d: %w", TotalHeaderLen, n, err)
		}

		return nil, nil, fmt.Errorf("failed to read header, expected %d bytes: %w, ", TotalHeaderLen, err)
	}

	offset := 0

	copy(header.MagicNumber[:], headerBuf[offset:offset+magicNumberLen])
	offset += magicNumberLen
	if !bytes.Equal(header.MagicNumber[:], []byte(MagicNumber)) {
		return nil, nil, fmt.Errorf("invalid magic number: expected %q, got %q", MagicNumber, header.MagicNumber)
	}

	header.Version = Version(headerBuf[offset])
	offset += versionLen
	if header.Version != VersionV1 {
		return nil, nil, fmt.Errorf("invalid version: expected version %s, got %s", VersionV1, header.Version)
	}

	copy(header.CipherTextKeySalt[:], headerBuf[offset:offset+SaltLen])
	offset += SaltLen

	copy(header.CipherTextKeyNonce[:], headerBuf[offset:offset+NonceLen])
	offset += NonceLen

	copy(header.cipherTextKeyKDFParamsRaw[:], headerBuf[offset:offset+kdfLen])
	offset += kdfLen

	header.TotalPayloadLength = binary.BigEndian.Uint16(headerBuf[offset : offset+totalFileLengthLen])
	offset += totalFileLengthLen

	copy(header.HMAC[:], headerBuf[offset:offset+hmacLen])

	kdfParams, err := parseKDFParams(header.cipherTextKeyKDFParamsRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse kdf params: %w", err)
	}
	header.CipherTextKeyKDFParams = *kdfParams

	buf, err := r.Peek(r.Buffered())
	if err != nil {
		return nil, nil, fmt.Errorf("internal error: %w", err)
	}

	payload := io.MultiReader(bytes.NewReader(buf), input)
	return &header, payload, nil
}

func EncodeHeader(output io.Writer, mac hash.Hash, salt [SaltLen]byte, nonce [NonceLen]byte, kdfParams KDFParams, cipherTextLen uint16) error {
	w := io.MultiWriter(output, mac)

	if _, err := w.Write([]byte(MagicNumber)); err != nil {
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

	kdfParamsBytes, err := encodeKDFParams(&kdfParams)
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

		return nil, fmt.Errorf("read ciphertext: %w", err)
	}

	return cipherText, nil
}
