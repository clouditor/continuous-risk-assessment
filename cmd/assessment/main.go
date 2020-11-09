package main

import "clouditor.io/riskAssessment/internal/assessment"

const (
	// File names for evaluation
	threatProfileDataInputFileName string = "resources/inputs/minimaltemplate.json"
	threatProfileDir               string = "resources/threat_profiles/minimalpolicy.rego"
	threatProfileOutputFileName    string = "./resources/outputs/regoEvaluation.json"

	// File names for attack tree reconstruction
	reconstructAttackTreesProfileDir       string = "./resources/reconstruction/"
	attackTreeReconstructionOutputFileName string = "./resources/outputs/momentary_attacktree.json"

	// File names for threat level evaluation
	threatLevelsProfileDir     string = "./resources/threatlevels/"
	threatLevelsOutputFileName string = "./resources/outputs/threat_levels.json"
)

func main() {
	// evaluate template against threat profiles
	evaluationResult := assessment.IdentifyThreatsFromTemplate(threatProfileDir, threatProfileDataInputFileName)
	assessment.SaveToJSONFile(threatProfileOutputFileName, evaluationResult)

	// reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction := assessment.ReconstructAttackTrees(reconstructAttackTreesProfileDir, evaluationResult)
	assessment.SaveToJSONFile(attackTreeReconstructionOutputFileName, attacktreeReconstruction)

	// identify highest threat level per asset
	threatLevels := assessment.IdentifyHighestThreatLevel(threatLevelsProfileDir, evaluationResult)
	assessment.SaveToJSONFile(threatLevelsOutputFileName, threatLevels)
}
