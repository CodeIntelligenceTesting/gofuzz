package flagutil

import (
	"os"

	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/pkg/log"
)

func BindFlag(flag string, flagSet *pflag.FlagSet) {
	if err := viper.BindPFlag(flag, flagSet.Lookup(flag)); err != nil {
		log.Errorf(err, "Failed to bind to flag %q", flag)
		os.Exit(1)
	}
}
