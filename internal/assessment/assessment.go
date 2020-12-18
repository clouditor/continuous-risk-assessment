package assessment

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/open-policy-agent/opa/rego"
)

// IdentifyThreatsFromIacTemplate compares an IaC template to Rego Threat Profiles, and outputs threats and vulnerable resources.
func IdentifyThreatsFromIacTemplate(threatProfileDir string, input interface{}) (results rego.ResultSet) {

	log.Info("Identify threats...")

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.threatprofile"),
		rego.Load([]string{threatProfileDir}, nil),
	).PrepareForEval(ctx)

	results, err = r.Eval(ctx, rego.EvalInput(input))

	if err != nil {
		log.Error("Rego evaluation error: ", err)
		log.Fatal(err)
		return nil
	}

	if results == nil {
		log.Info("Evaluation result is nil.")
		return nil
	}

	// log.Info("Result threats")
	// pretty.Print(results)

	return results
}

// ReconstructAttackTrees reassembles the output of IdentifyThreatsFromIacTemplate per asset, i.e. indicates the attack paths per asset.
func ReconstructAttackTrees(reconstructAttackTreesProfileDir string, data rego.ResultSet) (attacktrees rego.ResultSet) {

	log.Info("Reconstruct attack trees...")

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.reconstruction"),
		rego.Load([]string{reconstructAttackTreesProfileDir}, nil),
	).PrepareForEval(ctx)

	attacktrees, err = r.Eval(ctx, rego.EvalInput(data))
	if err != nil {
		log.Fatal(err)
	}

	// log.Info("Result reconstructed attack trees")
	// pretty.Print(attacktrees)

	return attacktrees
}

// CalculateRiskScores gets the highest threat level and impact level per asset/protection goal, and calculates a risk score.
func CalculateRiskScores(threatLevelsProfileDir string, evaluationResult rego.ResultSet) (threatlevels rego.ResultSet) {

	log.Info("Calculate risk scores...")

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("data.threatlevels"),
		rego.Load([]string{threatLevelsProfileDir}, nil),
	).PrepareForEval(ctx)

	threatlevels, err = r.Eval(ctx, rego.EvalInput(evaluationResult))
	if err != nil {
		log.Fatal(err)
	}

	// log.Info("Result highest threat level")
	// pretty.Print(threatlevels)

	return threatlevels
}
