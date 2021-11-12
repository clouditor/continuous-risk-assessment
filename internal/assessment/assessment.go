package assessment

import (
	"context"

	log "github.com/sirupsen/logrus"

	"github.com/open-policy-agent/opa/rego"
)

// IdentifyThreats compares an IaC template to Rego Threat Profiles, and outputs threats and vulnerable resources.
func IdentifyThreats(threatProfileDir string, input interface{}) (results rego.ResultSet) {

	log.Info("Identify threats...")

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.threatprofile"),
		rego.Load([]string{threatProfileDir}, nil),
	).PrepareForEval(ctx)

	if err != nil {
		log.Error("Prepare for evaluation error: ", err)
		log.Fatal(err)
		return nil
	}

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

	return results
}

// CwReconstruction reassembles the output of IdentifyThreats per asset, i.e. indicates the attack paths per asset.
func CwReconstruction(reconstructAttackTreesProfileDir string, data rego.ResultSet) (attacktrees rego.ResultSet) {

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

	return threatlevels
}
