package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/HallyG/vaultfile/internal/vault"
	"github.com/spf13/cobra"
)

var (
	BuildVersion  = `(missing)`
	BuildShortSHA = `(missing)`
)

func Main(ctx context.Context, args []string, output io.Writer) error {
	rootCmd := &cobra.Command{
		Use:   "vaultfile",
		Short: "Encrypt and decrypt content using pipes and the VaultFile format",
		Long: `vaultfile is a command-line tool for encrypting and decrypting content using pipes.
Input is read from stdin and output is written to stdout, making it easy to use
in shell pipelines and scripts.`,
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

	rootCmd.AddCommand(newCommand("decrypt", "Decrypt content from stdin to stdout", `cat encrypted.vault | vaultfile decrypt > plaintext.txt
  vaultfile decrypt < encrypted.vault > plaintext.txt`, false, decrypt))
	rootCmd.AddCommand(newCommand("encrypt", "Encrypt content from stdin to stdout", `cat plaintext.txt | vaultfile encrypt > encrypted.vault
  echo "secret data" | vaultfile encrypt > encrypted.vault`, true, encrypt))

	return rootCmd.ExecuteContext(ctx)
}

func newCommand(name string, short string, example string, confirmPassword bool, runFn processFunc) *cobra.Command {
	cmd := &cobra.Command{
		Use:     name,
		Short:   short,
		Example: example,
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: respect context
			inputBytes, err := io.ReadAll(cmd.InOrStdin())
			if err != nil {
				return fmt.Errorf("read input: %w", err)
			}

			password, err := PromptPassword(os.Stderr, confirmPassword)
			if err != nil {
				return fmt.Errorf("read password: %w", err)
			}

			logger := slog.Default()
			v, err := vault.New(vault.WithLogger(logger))
			if err != nil {
				return fmt.Errorf("create vault: %w", err)
			}

			return runFn(cmd.Context(), v, inputBytes, password, cmd.OutOrStdout())
		},
	}

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

func encrypt(ctx context.Context, v *vault.Vault, input []byte, password []byte, output io.Writer) error {
	if err := v.Encrypt(ctx, output, password, input); err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return nil
}

func decrypt(ctx context.Context, v *vault.Vault, input []byte, password []byte, output io.Writer) error {
	plainText, err := v.Decrypt(ctx, bytes.NewReader(input), password)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	if _, err := output.Write(plainText); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	return nil
}
