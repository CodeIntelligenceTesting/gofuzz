package sanitize

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/flagutil"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/log"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/sanitize"
	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/sanitizers"
	"github.com/CodeIntelligenceTesting/gofuzz/pkg/hook"
)

func New() *cobra.Command {
	var disabledSanitizers sanitizers.Sanitizers
	sanitizeCmd := &cobra.Command{
		Use:   "sanitize package",
		Short: "Add bug detection instrumentation.",
		Long:  "Add bug detection instrumentation to packages named by the import paths, along with their dependencies.",
		Args:  cobra.ExactArgs(1),
		PreRun: func(cmd *cobra.Command, args []string) {
			hook.ClearHooks()
			hook.RegisterDefaultHooks(disabledSanitizers)
			hook.SetSanitizersPackagePath(viper.GetString("sanitizers_package_path"))
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			overlayJSON, err := sanitize.Sanitize(args[0], &sanitize.Options{
				Include:          viper.GetStringSlice("include"),
				Exclude:          ignoredPatterns(),
				BuildFlags:       buildFlags(),
				OverwriteSources: viper.GetBool("overwrite_sources"),
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

	sanitizeCmd.PersistentFlags().StringP("tags", "t", "",
		"A comma-separated list of build tags to consider satisfied during the build")
	flagutil.BindFlag("tags", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().Bool("overwrite_sources", false,
		"Overwrite source files in place")
	flagutil.BindFlag("overwrite_sources", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().StringP("overlay", "o", "overlay.json",
		"Path of the overlay file to save paths to the instrumented source files")
	flagutil.BindFlag("overlay", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().StringP("sanitizers_package_path", "p",
		"github.com/CodeIntelligenceTesting/gofuzz/sanitizers",
		"Package path of the sanitizers package")
	flagutil.BindFlag("sanitizers_package_path", sanitizeCmd.PersistentFlags())

	sanitizeCmd.PersistentFlags().VarP(&disabledSanitizers, "disabled_sanitizers", "d",
		fmt.Sprintf("Set of sanitizers to disable. Possible values are: %s", strings.Join(sanitizers.AllSanitizers, ",")))

	return sanitizeCmd
}

func ignoredPatterns() []string {
	return append(viper.GetStringSlice("exclude"),
		// No reason to instrument these.
		"runtime/pprof",
		"runtime/race",

		// Do not instrument our sanitizers package
		viper.GetString("sanitizers_package_path"),
		filepath.Join(viper.GetString("sanitizers_package_path"), "detectors"),
		filepath.Join(viper.GetString("sanitizers_package_path"), "fuzzer"),
		filepath.Join(viper.GetString("sanitizers_package_path"), "reporter"),

		// transitive dependencies for the sanitizers module. To get these dependencies:
		// go list -json github.com/CodeIntelligenceTesting/gofuzz/sanitizers
		"bytes",
		"context",
		"database/sql",
		"database/sql/driver",
		"encoding",
		"encoding/base64",
		"encoding/binary",
		"encoding/json",
		"errors",
		"fmt",
		"html",
		"html/template",
		"internal/abi",
		"internal/bytealg",
		"internal/cpu",
		"internal/fmtsort",
		"internal/goarch",
		"internal/godebug",
		"internal/goexperiment",
		"internal/goos",
		"internal/itoa",
		"internal/oserror",
		"internal/poll",
		"internal/race",
		"internal/reflectlite",
		"internal/syscall/execenv",
		"internal/syscall/unix",
		"internal/testlog",
		"internal/unsafeheader",
		"io",
		"io/fs",
		"io/ioutil",
		"math",
		"math/bits",
		"net/url",
		"os",
		"os/exec",
		"path",
		"path/filepath",
		"reflect",
		"regexp",
		"regexp/syntax",
		"runtime",
		"runtime/cgo",
		"runtime/internal/atomic",
		"runtime/internal/math",
		"runtime/internal/sys",
		"runtime/internal/syscall",
		"sort",
		"strconv",
		"strings",
		"sync",
		"sync/atomic",
		"syscall",
		"text/template",
		"text/template/parse",
		"time",
		"unicode",
		"unicode/utf16",
		"unicode/utf8",
		"unsafe",
	)
}

func buildFlags() []string {
	tags := viper.GetString("tags")
	if tags != "" {
		return []string{
			fmt.Sprintf("-tags=%s", strings.Join(strings.Split(tags, ","), " ")),
		}
	}
	return []string{}
}
