package cmd

import (
	"context"
	"io"
	"log/slog"

	"github.com/spf13/cobra"
)

var (
	BuildVersion  = `(missing)`
	BuildShortSHA = `(missing)`
	rootCmd       = &cobra.Command{
		Use:     "vaultfile",
		Short:   "A CLI for encrypting and decrypting file content using the VaultFile format.",
		Version: BuildShortSHA,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}

			level := slog.LevelInfo
			if verbose {
				level = slog.LevelDebug
			}

			slog.SetDefault(
				slog.New(
					slog.NewTextHandler(cmd.ErrOrStderr(), &slog.HandlerOptions{
						Level: level,
					}),
				),
			)

			return nil
		},
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceUsage = true
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Enable verbose output")
}

func Main(ctx context.Context, args []string, output io.Writer) error {
	rootCmd.SetOut(output)
	rootCmd.SetArgs(args[1:])

	return rootCmd.ExecuteContext(ctx)
}
