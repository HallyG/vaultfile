package vaultfile

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/HallyG/vaultfile/internal/krypto/chacha"
	"github.com/HallyG/vaultfile/internal/krypto/key"
)

type Version uint8

const (
	VersionUnknown Version = 0
)

var (
	ErrInvalidHeader       = errors.New("invalid header format")
	ErrFileTruncated       = errors.New("file truncated")
	ErrInvalidHeaderHMAC   = errors.New("invalid HMAC")
	ErrInvalidKDFParams    = errors.New("invalid KDF parameters")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrKeyDerivationFailed = errors.New("key derivation failed")
	ErrInvalidPassword     = errors.New("invalid password")
	ErrNilWriter           = errors.New("writer is nil")
	ErrNilReader           = errors.New("reader is nil")
	ErrCipherTextTooLarge  = fmt.Errorf("ciphertext must be smaller than %d bytes", versionV1MaxCipherTextSize)
)

type VaultFileError struct {
	Err   error
	Field string
	Value any
}

func (e *VaultFileError) Error() string {
	return fmt.Sprintf("vault error: %s (field: %s, value: %v)", e.Err, e.Field, e.Value)
}

func (e *VaultFileError) Unwrap() error {
	return e.Err
}

func (v Version) String() string {
	return fmt.Sprintf("v%d", v)
}

type Vault struct {
	logger    *slog.Logger
	kdfParams *key.Argon2idParams
}

func WithLogger(logger *slog.Logger) func(*Vault) {
	return func(v *Vault) {
		v.logger = logger
	}
}

func New(opts ...func(*Vault)) (*Vault, error) {
	v := &Vault{
		kdfParams: key.DefaultArgon2idParams(),
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	v.logger = v.logger.
		WithGroup("vault").
		With(slog.String("version", VersionV1.String()))
	return v, nil
}

func (v *Vault) Version() Version {
	return VersionV1
}

func (v *Vault) Encrypt(ctx context.Context, w io.Writer, password []byte, plainText []byte) error {
	if w == nil {
		return &VaultFileError{
			Err:   ErrNilWriter,
			Field: "writer",
			Value: nil,
		}
	}

	v.logger.Debug("encrypting data", slog.Int("plaintext.size", len(plainText)))

	v.logger.Debug("generating salt", slog.Int("salt.size", key.MinSaltLength))
	salt, err := key.GenerateSalt(key.MinSaltLength)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to generate salt: %w", err),
			Field: "salt",
			Value: nil,
		}
	}

	cipher, err := v.deriveEncryptionKey(ctx, password, salt, v.kdfParams, chacha.KeySize)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "encryption_key",
			Value: nil,
		}
	}

	hmacKey, err := v.deriveHMACKey(ctx, password, salt, chacha.KeySize)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "hmac_key",
			Value: nil,
		}
	}

	v.logger.Debug("encrypting plaintext")
	cipherText, nonce, err := cipher.Encrypt(ctx, plainText, nil)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("encryption failed: %w", err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	if len(cipherText) > versionV1MaxCipherTextSize {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: ciphertext size %d exceeds maximum %d", ErrCipherTextTooLarge, len(cipherText), versionV1MaxCipherTextSize),
			Field: "ciphertext",
			Value: len(cipherText),
		}
	}

	v.logger.Debug("encrypted plaintext", slog.Int("nonce.size", len(nonce)), slog.Int("ciphertext.size", len(cipherText)))
	return v.writeBinary(w, salt, nonce, v.kdfParams, cipherText, hmacKey)
}

func (v *Vault) Decrypt(ctx context.Context, r io.Reader, password []byte) ([]byte, error) {
	if r == nil {
		return nil, &VaultFileError{
			Err:   ErrNilReader,
			Field: "reader",
			Value: nil,
		}
	}

	v.logger.Debug("decrypting data")

	header, err := v.readHeader(ctx, r)
	if err != nil {
		return nil, err
	}

	parsedKdfParams, err := v.parseKDFParams(ctx, header.kdfParams)
	if err != nil {
		return nil, err
	}

	computedHMAC, err := v.computeHMAC(ctx, password, header)
	if err != nil {
		return nil, err
	}

	v.logger.Debug("validating header hmac")
	if subtle.ConstantTimeCompare(computedHMAC, header.hmac) != 1 {
		return nil, &VaultFileError{
			Err:   ErrInvalidHeaderHMAC,
			Field: "hmac",
			Value: nil,
		}
	}

	cipherText, err := v.readCipherText(ctx, r, header)
	if err != nil {
		return nil, err
	}

	v.logger.Debug("validating expected file size")
	totalLen := len(cipherText) + versionV1LenHeader
	if uint16(totalLen) != header.totalFileLength {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: expected %d bytes, read %d", ErrFileTruncated, header.totalFileLength, totalLen),
			Field: "total_file_length",
			Value: totalLen,
		}
	}

	plainText, err := v.decrypt(ctx, password, header.salt, header.nonce, parsedKdfParams, cipherText, chacha.KeySize)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrDecryptionFailed, err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return plainText, nil
}
