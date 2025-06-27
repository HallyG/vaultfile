package vaultfile

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/HallyG/vaultfile/internal/format"
	"github.com/HallyG/vaultfile/internal/krypto"
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
	ErrCipherTextTooLarge  = fmt.Errorf("ciphertext must be smaller than %d bytes", format.MaxCipherTextSize)
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

type Vault struct {
	logger    *slog.Logger
	kdfParams *krypto.Argon2idParams
}

func WithLogger(logger *slog.Logger) func(*Vault) {
	return func(v *Vault) {
		v.logger = logger
	}
}

func New(opts ...func(*Vault)) (*Vault, error) {
	v := &Vault{
		kdfParams: krypto.DefaultArgon2idParams(),
	}

	for _, opt := range opts {
		opt(v)
	}

	if v.logger == nil {
		v.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	v.logger = v.logger.
		WithGroup("vault").
		With(slog.String("version", format.VersionV1.String()))
	return v, nil
}

func (v *Vault) Version() format.Version {
	return format.VersionV1
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
	v.logger.Debug("generating salt", slog.Int("salt.size", krypto.MinSaltLength))

	salt, err := krypto.GenerateSalt(krypto.MinSaltLength)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to generate salt: %w", err),
			Field: "salt",
			Value: nil,
		}
	}

	cipher, err := v.deriveEncryptionKey(ctx, password, salt, v.kdfParams, krypto.ChaCha20KeySize)
	if err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err),
			Field: "encryption_key",
			Value: nil,
		}
	}

	hmacKey, err := v.deriveHMACKey(ctx, password, salt, krypto.ChaCha20KeySize)
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

	if len(cipherText) > format.MaxCipherTextSize {
		return &VaultFileError{
			Err:   ErrCipherTextTooLarge,
			Field: "ciphertext",
			Value: nil,
		}
	}

	v.logger.Debug("encrypted plaintext", slog.Int("nonce.size", len(nonce)), slog.Int("ciphertext.size", len(cipherText)))
	formatKDFParams := &format.KDFParams{
		MemoryKiB:     v.kdfParams.MemoryKiB,
		NumIterations: v.kdfParams.NumIterations,
		NumThreads:    v.kdfParams.NumThreads,
	}

	// Use format package for encoding with HMAC
	mac := hmac.New(sha256.New, hmacKey)
	if err := format.Encode(w, mac, [16]byte(salt), [24]byte(nonce), *formatKDFParams, uint16(len(cipherText))); err != nil {
		return err
	}

	// Write ciphertext
	if _, err := w.Write(cipherText); err != nil {
		return &VaultFileError{
			Err:   fmt.Errorf("failed to write ciphertext: %w", err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return nil
}

func (v *Vault) Decrypt(ctx context.Context, input io.Reader, password []byte) ([]byte, error) {
	if input == nil {
		return nil, &VaultFileError{Err: ErrNilReader, Field: "reader", Value: nil}
	}

	v.logger.Debug("decrypting data")

	header, r, err := format.Parse(input)
	if err != nil {
		return nil, fmt.Errorf("reading header: %w", err)
	}

	// Parse KDF params using format package
	kdfParams, err := header.ParseKDFParams()
	if err != nil {
		return nil, &VaultFileError{Err: err, Field: "kdf_params", Value: nil}
	}

	// Convert to internal KDF params type if needed
	internalKDFParams := &krypto.Argon2idParams{
		MemoryKiB:     kdfParams.MemoryKiB,
		NumIterations: kdfParams.NumIterations,
		NumThreads:    kdfParams.NumThreads,
	}

	// Validate KDF params
	if err := internalKDFParams.Validate(ctx); err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrInvalidKDFParams, err),
			Field: "argon2id_params",
			Value: fmt.Sprintf("memory=%d, iterations=%d, threads=%d",
				kdfParams.MemoryKiB, kdfParams.NumIterations, kdfParams.NumThreads),
		}
	}

	// Derive HMAC key and validate
	hmacKey, err := v.deriveHMACKey(ctx, password, header.CipherTextKeySalt[:], krypto.ChaCha20KeySize)
	if err != nil {
		return nil, err
	}

	// Use format package for HMAC validation
	if err := format.ValidateMAC(header, hmac.New(sha256.New, hmacKey)); err != nil {
		return nil, &VaultFileError{Err: ErrInvalidHeaderHMAC, Field: "hmac", Value: nil}
	}

	// Use format package to read ciphertext
	cipherText, err := format.ReadCipherText(r, header)
	if err != nil {
		return nil, &VaultFileError{Err: err, Field: "ciphertext", Value: nil}
	}

	// Validate total file length
	totalLen := len(cipherText) + format.TotalHeaderLen
	if uint16(totalLen) != header.TotalPayloadLength {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: expected %d bytes, read %d", ErrFileTruncated, header.TotalPayloadLength, totalLen),
			Field: "total_file_length",
			Value: totalLen,
		}
	}

	// Decrypt
	cipher, err := v.deriveEncryptionKey(ctx, password, header.CipherTextKeySalt[:], internalKDFParams, krypto.ChaCha20KeySize)
	if err != nil {
		return nil, err
	}

	plainText, err := cipher.Decrypt(ctx, cipherText, header.CipherTextKeyNonce[:], nil)
	if err != nil {
		return nil, &VaultFileError{
			Err:   fmt.Errorf("%w: %v", ErrDecryptionFailed, err),
			Field: "ciphertext",
			Value: nil,
		}
	}

	return plainText, nil
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
