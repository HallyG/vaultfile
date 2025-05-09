package krypto

import (
	"context"
)

type Krypto interface {
	Encrypt(ctx context.Context, plainText []byte, additionalData []byte) (cipherText []byte, nonce []byte, err error)
	Decrypt(ctx context.Context, cipherText []byte, nonce []byte, additionalData []byte) (plainText []byte, err error)
}
