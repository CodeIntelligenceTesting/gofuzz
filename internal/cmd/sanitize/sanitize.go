package sanitize

import (
	"encoding/json"
	"os"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/flagutil"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/log"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/sanitize"
	"github.com/CodeIntelligenceTesting/gofuzz/pkg/hook"
)

func New() *cobra.Command {
	sanitizeCmd := &cobra.Command{
		Use:   "sanitize package",
		Short: "Add bug detection instrumentation.",
		Long:  "Add bug detection instrumentation to packages named by the import paths, along with their dependencies.",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			hook.RegisterDefaultHooks()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			overlayJSON, err := sanitize.Sanitize(args[0], &sanitize.Options{
				Include:   viper.GetStringSlice("include"),
				Exclude:   ignoredPatterns(),
				BuildTags: viper.GetStringSlice("tags"),
			})
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(overlayJSON, "", " ")
			if err != nil {
				return err

			}

			overlayFile := viper.GetString("overlay")
			file, err := os.OpenFile(overlayFile, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o755)
			if err != nil {
				return errors.Errorf("Failed to create the overlay file: %v", err)
			}

			_, err = file.Write(data)
			if err != nil {
				return errors.Errorf("Failed to write to the overlay file: %v", err)
			}
			log.Successf("File path replacements for the instrumented files are written to %s", overlayFile)
			return nil
		},
	}

	sanitizeCmd.PersistentFlags().StringArrayP("include", "i", []string{"*"},
		"A list of import paths to include")
	flagutil.BindFlag("include", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().StringArrayP("exclude", "e", []string{},
		"A list of import paths to exclude")
	flagutil.BindFlag("exclude", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().StringArrayP("tags", "t", []string{},
		"A list of build tags to consider satisfied during the build")
	flagutil.BindFlag("tags", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().StringP("overlay", "o", "overlay.json",
		"Path of the overlay file to save paths to the instrumented source files")
	flagutil.BindFlag("overlay", sanitizeCmd.PersistentFlags())

	return sanitizeCmd
}

func ignoredPatterns() []string {
	return append(viper.GetStringSlice("exclude"),
		// No reason to instrument these.
		"unsafe",
		"runtime/cgo",
		"runtime/pprof",
		"runtime/race",

		// https://github.com/google/oss-fuzz/issues/3639
		"syscall",

		// Do not instrument our sanitizers package
		"github.com/CodeIntelligenceTesting/gofuzz/sanitizers",
	)
}
