package cmd

import (
	"github.com/spf13/cobra"
)

const version = "1.0"

var (
	rootCmd        = &cobra.Command{Use: "equinix-metal-k8s"}
	project, token string
	verbose        bool
)

func init() {
	rootCmd.AddCommand(createCmd)
	createInit()

	rootCmd.PersistentFlags().StringVar(&project, "project", "", "project ID")
	rootCmd.PersistentFlags().StringVar(&token, "token", "", "Equinix Metal token, defaults to ~/.config/equinix/metal.yaml content")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "print lots of output to stderr")
}

// Execute primary function for cobra
func Execute() {
	rootCmd.Execute()
}
