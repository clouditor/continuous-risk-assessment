package main

import "clouditor.io/riskAssessment/internal/assessment"

func main() {
	// evaluate template against threat profiles
	evaluationResult := assessment.EvaluatePolicy("resources/threat_profiles/minimalpolicy.rego")
	assessment.SaveToJSONFile("./resources/outputs/regoEvaluation.json", evaluationResult)

	// reconstruct attack paths, i.e. identify all attack paths per asset
	attacktree_reconstruction := assessment.Reconstruct_attacktrees(evaluationResult)
	assessment.SaveToJSONFile("./resources/outputs/momentary_attacktree.json", attacktree_reconstruction)

	// identify highest threat level per asset
	threat_levels := assessment.Identify_highest_threat_level(evaluationResult)
	assessment.SaveToJSONFile("./resources/outputs/threat_levels.json", threat_levels)
}
