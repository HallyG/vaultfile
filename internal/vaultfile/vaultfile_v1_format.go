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

	"github.com/HallyG/vaultfile/internal/format"
	"github.com/HallyG/vaultfile/internal/krypto"
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

func (v *Vault) decrypt(ctx context.Context, password []byte, salt []byte, nonce []byte, kdfParams *krypto.Argon2idParams, cipherText []byte, keySize uint32) ([]byte, error) {
	cipher, err := v.deriveEncryptionKey(ctx, password, salt, kdfParams, keySize)
	if err != nil {
		return nil, err
	}

	return cipher.Decrypt(ctx, cipherText, nonce, nil)
}

func (v *Vault) writeBinary(w io.Writer, salt []byte, nonce []byte, kdfParams *krypto.Argon2idParams, cipherText []byte, hmacKey []byte) error {
	kdfParamsArr := bytes.NewBuffer(nil)
	if err := v.writeKDFParams(kdfParamsArr, kdfParams); err != nil {
		return err
	}

	mac := hmac.New(sha256.New, hmacKey)
	if err := format.Encode(w, mac, [16]byte(salt), [24]byte(nonce), [9]byte(kdfParamsArr.Bytes()), uint16(len(cipherText))); err != nil {
		return err
	}

	if _, err := w.Write(cipherText); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write ciphertext: %w", err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return nil
}

func (v *Vault) readCipherText(_ context.Context, r io.Reader, header *format.Header) ([]byte, error) {
	if header.TotalPayloadLength < uint16(versionV1LenHeader) {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: total file length %d is smaller than header length %d", ErrInvalidHeader, header.TotalPayloadLength, versionV1LenHeader),
			Field: "total_file_length",
			Value: header.TotalPayloadLength,
		}
	}

	cipherTextLen := int(header.TotalPayloadLength) - versionV1LenHeader
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

func (v *Vault) computeHMAC(ctx context.Context, password []byte, header *format.Header) ([]byte, error) {
	v.logger.Debug("verifying header hmac")

	hmacKey, err := v.deriveHMACKey(ctx, password, header.CipherTextKeySalt[:], krypto.ChaCha20KeySize)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, hmacKey)
	if _, err := mac.Write(header.MagicNumber[:]); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write magic to HMAC: %w", err),
			Field: "hmac_magic",
			Value: nil,
		}
	}
	if _, err := mac.Write([]byte{byte(header.Version)}); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write version to HMAC: %w", err),
			Field: "hmac_version",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.CipherTextKeySalt[:]); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write salt to HMAC: %w", err),
			Field: "hmac_salt",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.CipherTextKeyNonce[:]); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write nonce to HMAC: %w", err),
			Field: "hmac_nonce",
			Value: nil,
		}
	}
	if _, err := mac.Write(header.CipherTextKeyKDFParams[:]); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("failed to write KDF params to HMAC: %w", err),
			Field: "hmac_kdf_params",
			Value: nil,
		}
	}
	if err := binary.Write(mac, binary.BigEndian, header.TotalPayloadLength); err != nil {
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
	kdfParams := krypto.DefaultArgon2idParams()
	v.logger.Debug("deriving hmac key", slog.Group("key.hmac",
		slog.Int("size", int(keySize)),
		slog.Int("salt.size", len(salt)),
		slog.Group("argon2id",
			slog.Int("memory_kib", int(kdfParams.MemoryKiB)),
			slog.Int("num_iterations", int(kdfParams.NumIterations)),
			slog.Int("num_threads", int(kdfParams.NumThreads)),
		)),
	)

	return krypto.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
}

func (v *Vault) deriveEncryptionKey(ctx context.Context, password []byte, salt []byte, kdfParams *krypto.Argon2idParams, keySize uint32) (krypto.Krypto, error) {
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

	key, err := krypto.DeriveKeyFromPassword(ctx, password, salt, kdfParams, keySize)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "encryption_key",
			Value: nil,
		}
	}

	cipher, err := krypto.NewChaCha20Crypto(key)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: failed to initialize cipher: %v", ErrKeyDerivationFailed, err),
			Field: "cipher",
			Value: nil,
		}
	}
	return cipher, nil
}

func (v *Vault) writeKDFParams(w io.Writer, kdfParams *krypto.Argon2idParams) error {
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

func (v *Vault) parseKDFParams(ctx context.Context, data []byte) (*krypto.Argon2idParams, error) {
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

	params := &krypto.Argon2idParams{
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
