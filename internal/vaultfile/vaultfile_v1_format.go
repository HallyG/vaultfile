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
