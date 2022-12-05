package flagutil

import (
	"os"

	"code-intelligence.com/cifuzz/pkg/log"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func BindFlag(flag string, flagSet *pflag.FlagSet) {
	if err := viper.BindPFlag(flag, flagSet.Lookup(flag)); err != nil {
		log.Errorf(err, "Failed to bind to flag %q", flag)
		os.Exit(1)
	}
}
