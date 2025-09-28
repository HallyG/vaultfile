package cmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/spf13/cobra"
)

const (
	defaultFilePermissions = 0600
)

var (
	BuildVersion  = `(missing)`
	BuildShortSHA = `(missing)`
)

func Main(ctx context.Context, args []string, output io.Writer) error {
	rootCmd := &cobra.Command{
		Use:     "vaultfile",
		Short:   "A CLI for encrypting and decrypting file content using the VaultFile format.",
		Version: BuildShortSHA,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}

			setupLogging(verbose, cmd.ErrOrStderr())

			return nil
		},
	}
	rootCmd.SetErr(output)
	rootCmd.SetArgs(args[1:])
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "enable verbose logging")
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceUsage = true
	rootCmd.SilenceErrors = true

	rootCmd.AddCommand(newCommand("decrypt", "decrypt content from a file", "vaultfile decrypt --input encrypted.vault --output decrypted.txt", decrypt))
	rootCmd.AddCommand(newCommand("encrypt", "encrypt content from a file", "vaultfile encrypt --input plaintext.txt --output encrypted.vault", encrypt))

	return rootCmd.ExecuteContext(ctx)
}

func newCommand(name string, short string, example string, runFn processFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:     name,
		Short:   short,
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			input, err := cmd.Flags().GetString("input")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			output, err := cmd.Flags().GetString("output")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			return processContent(cmd.Context(), input, output, force, true, runFn)
		},
	}

	cmd.Flags().StringP("input", "i", "", "Input `file`")
	cmd.Flags().StringP("output", "o", "", "Output `file` (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Overwrite existing output file")

	return cmd
}

func setupLogging(verbose bool, output io.Writer) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(output, &slog.HandlerOptions{
		Level: level,
	})

	slog.SetDefault(slog.New(handler))
}

type processFunc func(ctx context.Context, v *vault.Vault, input []byte, password []byte, output io.Writer) error

func processContent(ctx context.Context, input string, output string, force bool, confirmPassword bool, pf processFunc) error {
	// check if input file exists (if specified)
	if input != "" {
		if _, err := os.Stat(input); os.IsNotExist(err) {
			return fmt.Errorf("input file does not exist: %s", input)
		}
	}

	// check if we can write to output (if specified and not forcing)
	if output != "" && !force {
		if _, err := os.Stat(output); err == nil {
			return fmt.Errorf("output file already exists: %s (use --force to overwrite)", output)
		}
	}

	// validate that force is only used with output
	if force && output == "" {
		return errors.New("--force can only be used with --output")
	}

	inputBytes, err := readInput(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	password, err := PromptPassword(nil, os.Stderr, confirmPassword)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer ZeroPassword(password)

	logger := slog.Default()
	v, err := vault.New(vault.WithLogger(logger))
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	w, close, err := openOutput(output, force)
	if err != nil {
		return fmt.Errorf("failed to open output: %w", err)
	}
	defer func() {
		if err := close(); err != nil {
			logger.ErrorContext(ctx, "failed to close file", slog.String("file", output))
		}
	}()

	return pf(ctx, v, inputBytes, password, w)
}

func encrypt(ctx context.Context, v *vault.Vault, input []byte, password []byte, output io.Writer) error {
	if err := v.Encrypt(ctx, output, password, input); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	return nil
}

func decrypt(ctx context.Context, v *vault.Vault, input []byte, password []byte, output io.Writer) error {
	plainText, err := v.Decrypt(ctx, bytes.NewReader(input), password)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if _, err := output.Write(plainText); err != nil {
		return fmt.Errorf("failed to write output: %w", err)
	}

	return nil
}

func readInput(path string) ([]byte, error) {
	path = filepath.Clean(path)

	if path == "" {
		return nil, fmt.Errorf("input file is required")
	}

	return os.ReadFile(path)
}

func openOutput(path string, force bool) (io.Writer, func() error, error) {
	path = filepath.Clean(path)

	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}

	if _, err := os.Stat(path); err == nil && !force {
		return nil, nil, fmt.Errorf("output file %q already exists; use --force to overwrite", path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, defaultFilePermissions)
	if err != nil {
		return nil, nil, err
	}

	return f, func() error { return f.Close() }, nil
}
