package main

import "clouditor.io/riskAssessment/internal/assessment"

func main() {
	// assessment.EvaluateExamplePolicy("resources/example_policy.rego")
	// assessment.EvaluatePolicy("resources/testPolicy.txt", "resources/testTemplate.json")
	assessment.EvaluatePolicy()
}
