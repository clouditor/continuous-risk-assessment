package main

import (
	"os"

	cmd "clouditor.io/riskAssessment/cmd/assessment"
	log "github.com/sirupsen/logrus"
)

func main() {

	log.SetLevel(log.DebugLevel)

	if err := cmd.CmdAssessment.Execute(); err != nil {
		os.Exit(1)
	}
}
