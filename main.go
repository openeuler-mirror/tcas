package main

import (
	"os"
	"tcas/cmd"
	_ "tcas/routers"
)

func main() {
	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}
