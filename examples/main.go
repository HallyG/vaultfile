package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/HallyG/vaultfile/internal/vaultfile"
)

func main() {
	ctx := context.Background()
	password := []byte("super secure password")
	plainText := []byte("hello, world!")
	output := bytes.NewBuffer(nil)

	vault, err := vaultfile.New()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("encrypting")
	fmt.Println("	plaintext:", string(plainText))
	err = vault.Encrypt(ctx, output, password, plainText)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}
	fmt.Println("	ciphertext:", output.Bytes())

	fmt.Println("decrypting")
	fmt.Println("	ciphertext:", output.Bytes())
	decrypted, err := vault.Decrypt(ctx, bytes.NewBuffer(output.Bytes()), password)
	if err != nil {
		log.Fatalf("failed to decrypt: %v", err)
	}
	fmt.Println("	plaintext:", string(decrypted))
}
