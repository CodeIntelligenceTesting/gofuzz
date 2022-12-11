package root

import (
	"os"

	"github.com/spf13/cobra"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/cmd/sanitize"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/flagutil"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/log"
)

func New() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:           "gofuzz",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.PersistentFlags().BoolP("help", "h", false, "Show help for command")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Show verbose output")
	flagutil.BindFlag("verbose", rootCmd.PersistentFlags())

	rootCmd.AddCommand(sanitize.New())

	return rootCmd
}

func Execute() {
	rootCmd := New()

	if _, err := rootCmd.ExecuteC(); err != nil {
		log.Errorf(err, "%v", err.Error())
		os.Exit(1)
	}
}
