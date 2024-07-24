package cmd

import (
	"github.com/spf13/cobra"
	"tcas/cmd/start"
	"tcas/cmd/version"
	"tcas/initial"
)

// NewCommand returns a new cobra.Command implementing the root command
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Args:         cobra.NoArgs,
		Use:          "tcas",
		Short:        "tcas is trust cluster attestation server",
		Long:         "",
		SilenceUsage: true,
	}

	initial.InitLog()

	cmd.AddCommand(start.NewCommand())
	cmd.AddCommand(version.NewCommand())
	return cmd
}

func Run() error {
	return NewCommand().Execute()
}
