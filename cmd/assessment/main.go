package main

import (
	"fmt"
	"os"

	"clouditor.io/riskAssessment/internal/assessment"
)

const (
	// File names for evaluation
	threatProfileDataInputFileName string = "resources/inputs/use_case_template.json"
	threatProfileDir               string = "resources/threatprofiles/use_case_policy.rego"
	threatProfileOutputFileName    string = "./resources/outputs/threats.json"

	// File names for attack tree reconstruction
	reconstructAttackTreesProfileDir       string = "./resources/reconstruction/"
	attackTreeReconstructionOutputFileName string = "./resources/outputs/momentary_attacktree.json"

	// File names for threat level evaluation
	threatLevelsProfileDir     string = "./resources/threatlevels/"
	threatLevelsOutputFileName string = "./resources/outputs/threatlevels.json"
)

func doCmd() (err error) {
	// evaluate template against threat profiles
	identifiedThreats := assessment.IdentifyThreatsFromTemplate(threatProfileDir, threatProfileDataInputFileName)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	assessment.SaveToFilesystem(threatProfileOutputFileName, identifiedThreats)

	// reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction := assessment.ReconstructAttackTrees(reconstructAttackTreesProfileDir, identifiedThreats)

	if attacktreeReconstruction == nil {
		fmt.Println("Attack tree reconstruction result is nil.")
	}

	assessment.SaveToFilesystem(attackTreeReconstructionOutputFileName, attacktreeReconstruction)

	// calculate risk scores per asset/protection goal
	threatLevels := assessment.CalculateRiskScores(threatLevelsProfileDir, identifiedThreats)

	if threatLevels == nil {
		fmt.Println("Identifying threat level result is nil.")
	}

	assessment.SaveToFilesystem(threatLevelsOutputFileName, threatLevels)

	return nil
}

func main() {
	if err := doCmd(); err != nil {
		os.Exit(1)
	}
}
