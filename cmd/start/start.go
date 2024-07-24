package start

import (
	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/spf13/cobra"
	"tcas/initial"
	"tcas/server"
)

// NewCommand returns a new cobra.Command for exec
func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:                "start",
		Args:               cobra.ArbitraryArgs,
		FParseErrWhitelist: cobra.FParseErrWhitelist{UnknownFlags: true},
		Short:              "start up tcas",
		Long:               "start up trust cluster attestation server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runE(cmd, args)
		},
	}
	return cmd
}

func runE(cmd *cobra.Command, args []string) error {
	initial.TeesInit()
	initial.InitDbSqlite()
	initial.EndorsementInit()
	initial.InitNonceManger()
	logs.Info("tcas is Running in %s mode", server.GetMode())
	beego.Run()
	return nil
}
