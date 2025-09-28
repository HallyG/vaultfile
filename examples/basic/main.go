package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/HallyG/vaultfile/internal/vault"
)

func main() {
	fmt.Println("Basic VaultFile Example")
	fmt.Println("======================")

	ctx := context.Background()
	password := []byte("super secure password")
	plainText := []byte("hello, world!")

	v, err := vault.New()
	if err != nil {
		log.Fatal(err)
	}

	// Basic encryption
	fmt.Println("\n1. Basic Encryption:")
	fmt.Println("   plaintext:", string(plainText))

	var output bytes.Buffer
	err = v.Encrypt(ctx, &output, password, plainText)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}
	fmt.Printf("   encrypted size: %d bytes\n", output.Len())

	// Basic decryption
	fmt.Println("\n2. Basic Decryption:")
	fmt.Printf("   ciphertext size: %d bytes\n", output.Len())

	decrypted, err := v.Decrypt(ctx, &output, password)
	if err != nil {
		log.Fatalf("failed to decrypt: %v", err)
	}
	fmt.Println("   decrypted:", string(decrypted))
}
