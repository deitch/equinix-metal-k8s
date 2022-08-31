package cmd

import (
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const version = "1.0"

const (
	envPrefix                  = "METAL"
	configFileWithoutExtension = "metal"
	defaultConfigDir           = ".config/equinix"
	MetalTokenEnvVar           = envPrefix + "AUTH_TOKEN"
	MetalConfigFile            = "~/" + defaultConfigDir + "/" + configFileWithoutExtension + ".yaml"
)

var (
	rootCmd = &cobra.Command{
		Use: "equinix-metal-k8s",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			// set the auth token
			v := viper.New()
			v.AddConfigPath(defaultConfigPath())
			v.SetConfigName(configFileWithoutExtension)
			v.SetConfigType("yaml")

			if err := v.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					panic(fmt.Errorf("could not read config: %s", err))
				}
			}

			v.SetEnvPrefix(envPrefix)
			v.AutomaticEnv()
			token = v.GetString("token")
		},
	}
	project, token string
	verbose        bool
)

func init() {
	rootCmd.AddCommand(createCmd)
	createInit()

	rootCmd.PersistentFlags().StringVar(&project, "project", "", "project ID")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", fmt.Sprintf("Equinix Metal token, overrides env var %s, which overrides %s", MetalTokenEnvVar, MetalConfigFile))
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "print lots of output to stderr")
}

// Execute primary function for cobra
func Execute() {
	rootCmd.Execute()
}

func defaultConfigPath() string {
	return path.Join(userHomeDir(), defaultConfigDir)
}

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}
