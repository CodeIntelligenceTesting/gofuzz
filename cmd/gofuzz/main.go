package main

import (
	"strings"

	"github.com/spf13/viper"

	"github.com/CodeIntelligenceTesting/gofuzz/internal/cmd/root"
)

func init() {
	viper.SetEnvPrefix("GOFUZZ")
	viper.AutomaticEnv()
	// need to make GOFUZZ_MY_VAR available as viper.Get("my-var")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func main() {
	root.Execute()
}
