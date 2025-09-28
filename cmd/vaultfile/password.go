package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"golang.org/x/term"
)

// PromptPassword prompts for and reads a password from the terminal.
// When stdin is being used for piped data, it automatically opens /dev/tty
// to read the password directly from the terminal instead.
func PromptPassword(promptOutput io.Writer, confirmPassword bool, logger *slog.Logger) ([]byte, error) {
	if promptOutput == nil {
		return nil, errors.New("output writer cannot be nil")
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		// When stdin is used for data (pipes), open terminal device for password input
		// TODO: Use "CON" on Windows instead of "/dev/tty"
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("allocating terminal for password input: %w", err)
		}
		defer func() {
			if err := tty.Close(); err != nil {
				logger.Warn("failed to close allocated terminal", slog.Any("err", err))
			}
		}()

		fd = int(tty.Fd())
	}

	_, _ = fmt.Fprint(promptOutput, "Enter password: ")
	password, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	_, _ = fmt.Fprintln(promptOutput)

	if len(password) == 0 {
		return nil, errors.New("password cannot be empty")
	}

	if !confirmPassword {
		return password, nil
	}

	_, _ = fmt.Fprint(promptOutput, "Confirm password: ")
	password2, err := term.ReadPassword(fd)
	if err != nil {
		return nil, fmt.Errorf(" read password confirmation: %w", err)
	}
	_, _ = fmt.Fprintln(promptOutput)

	if !bytes.Equal(password, password2) {
		return nil, errors.New("passwords do not match")
	}

	return password, nil
}
