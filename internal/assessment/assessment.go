package assessment

import (
	"context"
	"encoding/json"
	"io/ioutil"

	log "github.com/sirupsen/logrus"

	// "github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"

	"github.com/open-policy-agent/opa/rego"
)

// TODO Merge IdentifyThreatsFromTemplate and IdentifyThreatsFromARMTemplate
// IdentifyThreatsFromTemplate compares an ARM template (inputFile) to Rego Threat Profiles, and outputs threats and vulnerable resources.
// func IdentifyThreatsFromTemplate(threatProfileDir string, inputFile string) (results rego.ResultSet) {

// 	log.Info("Identify threats...")

// 	ctx := context.TODO()
// 	r, err := rego.New(
// 		rego.Query("x = data.threatprofile"),
// 		rego.Load([]string{threatProfileDir}, nil),
// 	).PrepareForEval(ctx)

// 	input := ReadFromFilesystem(inputFile)

// 	results, err = r.Eval(ctx, rego.EvalInput(input))

// 	if err != nil {
// 		log.Fatal(err)
// 		return nil
// 	}

// 	if results == nil {
// 		log.Info("Evaluation result is nil.")
// 		return nil
// 	}

// 	// log.Info("Result threats")
// 	// pretty.Print(results)

// 	return results
// }

// IdentifyThreatsFromARMTemplate compares an ARM template to Rego Threat Profiles, and outputs threats and vulnerable resources.
func IdentifyThreatsFromARMTemplate(threatProfileDir string, input interface{}) (results rego.ResultSet) {

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

// ReconstructAttackTrees reassembles the output of IdentifyThreatsFromTemplate per asset, i.e. indicates the attack paths per asset.
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

// ReadFromFileSystem reads files from the file system.
func ReadFromFilesystem(path string) interface{} {

	bs, err := ioutil.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	var input interface{}

	if err := json.Unmarshal(bs, &input); err != nil {
		log.Fatal(err)
	}
	return input
}

// SaveToFilesystem saves rego binding results to file system.
func SaveToFilesystem(filename string, data rego.ResultSet) {
	file, err := json.MarshalIndent(data, "", " ")

	if err != nil {
		log.Fatal("Error Marshal JSON data: ", err)
	}

	err = ioutil.WriteFile(filename, file, 0644)

	if err != nil {
		log.Fatal("Error saving file to file system: ", err)
	} else {
		log.Info("Saved data to ", filename)
	}

}
