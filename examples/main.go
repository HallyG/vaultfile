package main

import (
	"bytes"
	"context"
	"fmt"
	"log"

	"github.com/HallyG/vaultfile/internal/vault"
)

func main() {
	ctx := context.Background()
	password := []byte("super secure password")
	plainText := []byte("hello, world!")
	output := bytes.NewBuffer(nil)

	v, err := vault.New()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("encrypting")
	fmt.Println("	plaintext:", string(plainText))
	err = v.Encrypt(ctx, output, password, plainText)
	if err != nil {
		log.Fatalf("failed to encrypt: %v", err)
	}
	fmt.Println("	ciphertext len:", len(output.Bytes()))

	fmt.Println("decrypting")
	fmt.Println("	ciphertext len:", len(output.Bytes()))
	decrypted, err := v.Decrypt(ctx, bytes.NewBuffer(output.Bytes()), password)
	if err != nil {
		log.Fatalf("failed to decrypt: %v", err)
	}
	fmt.Println("	plaintext:", string(decrypted))
}
