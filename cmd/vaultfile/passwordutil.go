package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// PasswordReader defines an interface for reading passwords from a terminal-like input.
type PasswordReader interface {
	// IsTerminal reports whether the input is a terminal (TTY).
	IsTerminal() bool
	// ReadPassword writes the prompt to the output and reads a password from the input.
	ReadPassword(prompt string, output io.Writer) ([]byte, error)
}

type defaultPasswordReader struct{}

func (d *defaultPasswordReader) IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// ReadPassword prompts for and reads a password from os.Stdin.
func (d *defaultPasswordReader) ReadPassword(prompt string, output io.Writer) ([]byte, error) {
	if _, err := fmt.Fprint(output, prompt); err != nil {
		return nil, fmt.Errorf("failed to write prompt: %w", err)
	}

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("failed to read password: %w", err)
	}

	if _, err := fmt.Fprintln(output); err != nil {
		return nil, fmt.Errorf("failed to write newline: %w", err)
	}

	return password, nil
}

// PromptPassword reads a password from the input, optionally prompting for confirmation.
// If reader is nil, it uses defaultPasswordReader (os.Stdin).
func PromptPassword(reader PasswordReader, output io.Writer, confirm bool) ([]byte, error) {
	if reader == nil {
		reader = &defaultPasswordReader{}
	}

	if output == nil {
		return nil, errors.New("output writer cannot be nil")
	}

	if !reader.IsTerminal() {
		return nil, errors.New("password input requires a terminal (input is not a TTY)")
	}

	password, err := reader.ReadPassword("Enter password: ", output)
	if err != nil {
		return nil, err
	}

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if !confirm {
		return password, nil
	}

	confirmPassword, err := reader.ReadPassword("Confirm password: ", output)
	if err != nil {
		ZeroPassword(password)
		return nil, fmt.Errorf("failed to read confirmation password: %w", err)
	}

	if !bytes.Equal(password, confirmPassword) {
		ZeroPassword(password)
		ZeroPassword(confirmPassword)
		return nil, errors.New("passwords do not match")
	}

	ZeroPassword(confirmPassword)
	return password, nil
}

func ZeroPassword(password []byte) {
	for i := range password {
		password[i] = 0
	}
}
