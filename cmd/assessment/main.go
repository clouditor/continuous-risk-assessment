package main

import "clouditor.io/riskAssessment/internal/assessment"

func main() {
	result := assessment.EvaluatePolicy()
	assessment.SaveToJSONFile("./resources/outputs/regoEvaluation.json", result)
}
