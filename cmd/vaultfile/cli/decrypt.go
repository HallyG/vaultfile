package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/HallyG/vaultfile/internal/passwordutil"
	"github.com/HallyG/vaultfile/internal/vaultfile"
	"github.com/spf13/cobra"
)

const defaultFilePermssions = 0600

var (
	decryptCmd = &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt content from a file or stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPath, err := cmd.Flags().GetString("input")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			outputPath, err := cmd.Flags().GetString("output")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			return processContent(cmd.Context(), inputPath, outputPath, force, false, func(ctx context.Context, v *vaultfile.Vault, input []byte, password []byte, output io.Writer) error {
				plainText, err := v.Decrypt(ctx, bytes.NewReader(input), password)
				if err != nil {
					return fmt.Errorf("decryption failed: %w", err)
				}

				if _, err := output.Write(plainText); err != nil {
					return fmt.Errorf("failed to write output: %w", err)
				}

				return nil
			})
		},
	}

	encryptCmd = &cobra.Command{
		Use:   "encrypt",
		Short: "Encrypt content from a file or stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			inputPath, err := cmd.Flags().GetString("input")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			outputPath, err := cmd.Flags().GetString("output")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to get input flag: %w", err)
			}

			return processContent(cmd.Context(), inputPath, outputPath, force, true, func(ctx context.Context, v *vaultfile.Vault, input []byte, password []byte, output io.Writer) error {
				if err := v.Encrypt(ctx, output, password, input); err != nil {
					return fmt.Errorf("encryption failed: %w", err)
				}

				return nil
			})
		},
	}
)

func init() {
	rootCmd.AddCommand(encryptCmd, decryptCmd)
	configureFlags(encryptCmd)
	configureFlags(decryptCmd)
}

func configureFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("input", "i", "", "Input file")
	cmd.Flags().StringP("output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolP("force", "f", false, "Overwrite existing output file")
	_ = cmd.MarkFlagRequired("input")
}

type processFunc func(ctx context.Context, v *vaultfile.Vault, input []byte, password []byte, output io.Writer) error

func processContent(ctx context.Context, inputPath, outputPath string, force bool, confirmPassword bool, pf processFunc) error {
	input, err := readInput(inputPath)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	password, err := passwordutil.PromptPassword(nil, os.Stderr, confirmPassword)
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	defer passwordutil.ZeroPassword(password)

	v, err := vaultfile.New(vaultfile.WithLogger(slog.Default()))
	if err != nil {
		return fmt.Errorf("failed to create vault: %w", err)
	}

	w, closer, err := openOutput(outputPath, force)
	if err != nil {
		return fmt.Errorf("failed to open output: %w", err)
	}
	// nolint errcheck
	defer closer()

	return pf(ctx, v, input, password, w)
}

func readInput(path string) ([]byte, error) {
	if path == "" {
		return nil, fmt.Errorf("input file is required")
	}

	return os.ReadFile(path)
}

func openOutput(path string, force bool) (io.Writer, func() error, error) {
	if path == "" {
		return os.Stdout, func() error { return nil }, nil
	}

	if _, err := os.Stat(path); err == nil && !force {
		return nil, nil, fmt.Errorf("output file %q already exists; use --force to overwrite", path)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, defaultFilePermssions)
	if err != nil {
		return nil, nil, err
	}

	return f, func() error { return f.Close() }, nil
}
