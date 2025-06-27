// The VaultFile V1 binary format consists of a 88-byte header followed by the ciphertext.
// The header includes:
// - Magic Number (4 bytes): "HGVF"
// - Version (1 byte): 1
// - Salt (16 bytes): Random salt for key derivation
// - Nonce (24 bytes): Nonce for XChaCha20-Poly1305
// - KDF Parameters (9 bytes): Argon2id parameters (MemoryKiB, NumIterations, NumThreads)
// - Total File Length (2 bytes): Header + ciphertext length
// - HMAC (32 bytes): SHA-256 HMAC of the header fields
package vaultfile

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"

	"github.com/HallyG/vaultfile/internal/krypto"
	"github.com/HallyG/vaultfile/internal/krypto/chacha"
	"github.com/HallyG/vaultfile/internal/krypto/key"
)

const (
	VersionV1                   Version = 1
	VersionV1MagicNumber                = "HGVF"
	versionV1LenMagicNumber             = len(VersionV1MagicNumber)
	versionV1LenVersion                 = 1
	versionV1LenSalt                    = 16
	versionV1LenNonce                   = 24
	versionV1LenKDFMemoryKiB            = 4
	versionV1LenKDFIterations           = 4
	versionV1LenKDFThreads              = 1
	versionV1LenKDF                     = versionV1LenKDFMemoryKiB + versionV1LenKDFIterations + versionV1LenKDFThreads
	versionV1LenTotalFileLength         = 2
	versionV1LenHMAC                    = sha256.Size
	versionV1LenHeader                  = versionV1LenMagicNumber + versionV1LenVersion + versionV1LenSalt + versionV1LenNonce + versionV1LenKDF + versionV1LenTotalFileLength + versionV1LenHMAC
	versionV1MaxCipherTextSize          = math.MaxUint16
)

type VersionV1Header struct {
	magic           []byte
	version         Version
	salt            []byte
	nonce           []byte
	kdfParams       []byte
	totalFileLength uint16
	hmac            []byte
}

func (v *Vault) decrypt(ctx context.Context, password []byte, salt []byte, nonce []byte, kdfParams *key.Argon2idParams, cipherText []byte, keySize uint32) ([]byte, error) {
	cipher, err := v.deriveEncryptionKey(ctx, password, salt, kdfParams, keySize)
	if err != nil {
		return nil, err
	}

	return cipher.Decrypt(ctx, cipherText, nonce, nil)
}

func (v *Vault) writeBinary(w io.Writer, salt []byte, nonce []byte, kdfParams *key.Argon2idParams, cipherText []byte, hmacKey []byte) error {
	totalFileLength := uint16(versionV1LenHeader) + uint16(len(cipherText))

	header := bytes.NewBuffer(nil)
	header.Grow(versionV1LenHeader)
	mac := hmac.New(sha256.New, hmacKey)
	writer := io.MultiWriter(header, mac)

	if _, err := writer.Write([]byte(VersionV1MagicNumber)); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write magic number: %w", err),
			Field: "magic_number",
			Value: nil,
		}
	}

	if _, err := writer.Write([]byte{byte(VersionV1)}); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write version: %w", err),
			Field: "version",
			Value: nil,
		}
	}

	if _, err := writer.Write(salt); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write salt: %w", err),
			Field: "salt",
			Value: nil,
		}
	}

	if _, err := writer.Write(nonce); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write nonce: %w", err),
			Field: "nonce",
			Value: nil,
		}
	}

	if err := v.writeKDFParams(writer, kdfParams); err != nil {
		return err
	}

	if err := binary.Write(writer, binary.BigEndian, totalFileLength); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write total file length: %w", err),
			Field: "total_file_length",
			Value: nil,
		}
	}

	_, _ = header.Write(mac.Sum(nil))

	if _, err := w.Write(header.Bytes()); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write header: %w, expected %d bytes", err, versionV1LenHeader),
			Field: "header",
			Value: nil,
		}
	}

	if _, err := w.Write(cipherText); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write ciphertext: %w, expected %d bytes", err, len(cipherText)),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return nil
}

func (v *Vault) readHeader(_ context.Context, r io.Reader) (*VersionV1Header, error) {
	var headerBuf [versionV1LenHeader]byte
	header := headerBuf[:]

	if n, err := io.ReadFull(r, header); err != nil {
		if err == io.EOF || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &VaultFileError{
				Err:   fmt.Errorf("%w: incomplete header, expected %d bytes, read %d", ErrFileTruncated, versionV1LenHeader, n),
				Field: "header",
				Value: n,
			}
		}
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to read header: %w, expected %d bytes", err, versionV1LenHeader),
			Field: "header",
			Value: nil,
		}
	}

	start := 0
	end := versionV1LenMagicNumber
	magic := header[start:end]
	if !bytes.Equal(magic, []byte(VersionV1MagicNumber)) {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: expected %q, got %q", ErrInvalidHeader, VersionV1MagicNumber, magic),
			Field: "magic",
			Value: string(magic),
		}
	}

	start = end
	end = start + versionV1LenVersion
	version := Version(header[start])
	if version != VersionV1 {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: expected version %d, got %d", ErrInvalidHeader, VersionV1, version),
			Field: "version",
			Value: version,
		}
	}

	start = end
	end = start + versionV1LenSalt
	salt := header[start:end]

	start = end
	end = start + versionV1LenNonce
	nonce := header[start:end]

	start = end
	end = start + versionV1LenKDF
	kdfParams := header[start:end]

	start = end
	end = start + versionV1LenTotalFileLength
	if end > len(header) {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: header too short for total file length field", ErrInvalidHeader),
			Field: "header_length",
			Value: len(header),
		}
	}
	totalFileLength := binary.BigEndian.Uint16(header[start:end])

	start = end
	end = start + versionV1LenHMAC
	if end > len(header) {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: header too short for HMAC field", ErrInvalidHeader),
			Field: "header_length",
			Value: len(header),
		}
	}
	hmac := header[start:end]

	return &VersionV1Header{
		magic:           magic,
		version:         version,
		totalFileLength: totalFileLength,
		salt:            salt,
		nonce:           nonce,
		kdfParams:       kdfParams,
		hmac:            hmac,
	}, nil
}

func (v *Vault) readCipherText(_ context.Context, r io.Reader, header *VersionV1Header) ([]byte, error) {
	if header.totalFileLength < uint16(versionV1LenHeader) {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: total file length %d is smaller than header length %d", ErrInvalidHeader, header.totalFileLength, versionV1LenHeader),
			Field: "total_file_length",
			Value: header.totalFileLength,
		}
	}

	cipherTextLen := int(header.totalFileLength) - versionV1LenHeader
	if cipherTextLen < 0 {
		cipherTextLen = 0
	}
	cipherText := make([]byte, cipherTextLen)

	if n, err := io.ReadFull(r, cipherText); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, &VaultFileError{
				Err:   fmt.Errorf("%w: incomplete ciphertext, expected %d bytes, read %d", ErrFileTruncated, cipherTextLen, n),
				Field: "ciphertext",
				Value: n,
			}
		}
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to read ciphertext: %w, expected %d bytes", err, cipherTextLen),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return cipherText, nil
}

func (v *Vault) computeHMAC(ctx context.Context, password []byte, header *VersionV1Header) ([]byte, error) {
	v.logger.Debug("verifying header hmac")

	hmacKey, err := v.deriveHMACKey(ctx, password, header.salt, chacha.KeySize)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, hmacKey)
	if _, err := mac.Write(header.magic); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write magic to HMAC: %w", err),
			Field: "hmac_magic",
			Value: nil,
		}
	}
	if _, err := mac.Write([]byte{byte(header.version)}); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write version to HMAC: %w", err),
			Field: "hmac_version",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.salt); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write salt to HMAC: %w", err),
			Field: "hmac_salt",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.nonce); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write nonce to HMAC: %w", err),
			Field: "hmac_nonce",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.kdfParams); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write KDF params to HMAC: %w", err),
			Field: "hmac_kdf_params",
			Value: nil,
		}
	}
	if err := binary.Write(mac, binary.BigEndian, header.totalFileLength); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write total file length to HMAC: %w", err),
			Field: "hmac_total_length",
			Value: nil,
		}
	}
	return mac.Sum(nil), nil
}

func (v *Vault) deriveHMACKey(ctx context.Context, password []byte, salt []byte, keySize uint32) ([]byte, error) {
	// We use a predefined argon2id params so prevent a resource exhaustion attack where we'd need to generate the password from header values before we verify them
	kdfParams := key.DefaultArgon2idParams()
	v.logger.Debug("deriving hmac key", slog.Group("key.hmac",
		slog.Int("size", int(keySize)),
		slog.Int("salt.size", len(salt)),
		slog.Group("argon2id",
			slog.Int("memory_kib", int(kdfParams.MemoryKiB)),
			slog.Int("num_iterations", int(kdfParams.NumIterations)),
			slog.Int("num_threads", int(kdfParams.NumThreads)),
		)),
	)

	return key.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
}

func (v *Vault) deriveEncryptionKey(ctx context.Context, password []byte, salt []byte, kdfParams *key.Argon2idParams, keySize uint32) (krypto.Krypto, error) {
	v.logger.Debug("deriving encryption key", slog.Group("key.encryption",
		slog.String("alg", "chacha20poly1305"),
		slog.Int("size", int(keySize)),
		slog.Int("salt.size", len(salt)),
		slog.Group("argon2id",
			slog.Int("memory_kib", int(kdfParams.MemoryKiB)),
			slog.Int("num_iterations", int(kdfParams.NumIterations)),
			slog.Int("num_threads", int(kdfParams.NumThreads)),
		)),
	)

	key, err := key.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "encryption_key",
			Value: nil,
		}
	}

	cipher, err := chacha.New(key)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: failed to initialize cipher: %v", ErrKeyDerivationFailed, err),
			Field: "cipher",
			Value: nil,
		}
	}
	return cipher, nil
}

func (v *Vault) writeKDFParams(w io.Writer, kdfParams *key.Argon2idParams) error {
	v.logger.Debug("writing encryption key kdf params", slog.Group("key.encryption",
		slog.Group("argon2id",
			slog.Int("memory_kib", int(kdfParams.MemoryKiB)),
			slog.Int("num_iterations", int(kdfParams.NumIterations)),
			slog.Int("num_threads", int(kdfParams.NumThreads)),
		)),
	)

	if err := binary.Write(w, binary.BigEndian, kdfParams.MemoryKiB); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write KDF memory parameter: %w", err),
			Field: "kdf_memory",
			Value: nil,
		}
	}
	if err := binary.Write(w, binary.BigEndian, kdfParams.NumIterations); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write KDF iterations parameter: %w", err),
			Field: "kdf_iterations",
			Value: nil,
		}
	}
	if _, err := w.Write([]byte{kdfParams.NumThreads}); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write KDF threads parameter: %w", err),
			Field: "kdf_threads",
			Value: nil,
		}
	}
	return nil
}

func (v *Vault) parseKDFParams(ctx context.Context, data []byte) (*key.Argon2idParams, error) {
	v.logger.Debug("parsing encryption key kdf params")

	if len(data) != versionV1LenKDF {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: invalid KDF parameters length, expected %d bytes, got %d", ErrInvalidKDFParams, versionV1LenKDF, len(data)),
			Field: "kdf_params",
			Value: len(data),
		}
	}

	memoryKiB := binary.BigEndian.Uint32(data[0:4])
	numIterations := binary.BigEndian.Uint32(data[4:8])
	numThreads := uint8(data[8])

	params := &key.Argon2idParams{
		MemoryKiB:     memoryKiB,
		NumIterations: numIterations,
		NumThreads:    numThreads,
	}

	if err := params.Validate(ctx); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrInvalidKDFParams, err),
			Field: "argon2id_params",
			Value: fmt.Sprintf("memory=%d, iterations=%d, threads=%d", memoryKiB, numIterations, numThreads),
		}
	}

	return params, nil
}
