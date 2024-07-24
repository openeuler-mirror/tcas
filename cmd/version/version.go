package version

import (
	"fmt"
	"github.com/spf13/cobra"
	"tcas/server"
)

var version string

// NewCommand returns a new cobra.Command for exec
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "version",
		Args:               cobra.ArbitraryArgs,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		Short:              "the version of tcas",
		Long:               "the version of tcas",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("tcas's version is %s, mode in %s\n", server.GetVersion(), server.GetMode())
		},
	}
	return cmd
}
