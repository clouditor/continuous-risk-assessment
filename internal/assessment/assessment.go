package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/kr/pretty"
	"github.com/open-policy-agent/opa/rego"
)

// IdentifyThreatsFromTemplate identifies threats from template data.
func IdentifyThreatsFromTemplate(threatProfileDir string, inputFile string) (results rego.ResultSet) {

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.minimal"),
		rego.Load([]string{threatProfileDir}, nil),
	).PrepareForEval(ctx)

	input := jsonFileInput(inputFile)

	results, err = r.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Result evaluation")
	pretty.Print(results)
	fmt.Println()

	// for index, element := range results {
	// 	fmt.Println()
	// 	fmt.Println(element)
	// 	if err != nil {
	// 		// Which error?
	// 		// Handle evaluation error.
	// 	} else if len(results) == 0 {
	// 		// Handle undefined result.
	// 	} else if result, ok := results[index].Bindings["x"].(bool); !ok {
	// 		fmt.Println("Rego Bindings Result: ", result)
	// 	} else {
	// 		// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
	// 	}
	// }

	return results
}

// ReconstructAttackTrees reconstructs attack trees from threats.
func ReconstructAttackTrees(reconstructAttackTreesProfileDir string, data rego.ResultSet) (attacktrees rego.ResultSet) {
	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.reconstruction"),
		rego.Load([]string{reconstructAttackTreesProfileDir}, nil),
	).PrepareForEval(ctx)

	attacktrees, err = r.Eval(ctx, rego.EvalInput(data))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Result reconstructed attack trees")
	pretty.Print(attacktrees)
	fmt.Println()

	return attacktrees
}

// IdentifyHighestThreatLevel identifies highest threat level per asset.
func IdentifyHighestThreatLevel(threatLevelsProfileDir string, evaluationResult rego.ResultSet) (threatlevels rego.ResultSet) {

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("data.threatlevels"),
		rego.Load([]string{threatLevelsProfileDir}, nil),
	).PrepareForEval(ctx)

	threatlevels, err = r.Eval(ctx, rego.EvalInput(evaluationResult))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Result highest threat level")
	pretty.Print(threatlevels)
	fmt.Println()

	return threatlevels
}

func jsonFileInput(path string) interface{} {

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

// SaveToJSONFile saves rego binding results to file system.
func SaveToJSONFile(filename string, data rego.ResultSet) {
	file, err := json.MarshalIndent(data, "", " ")

	if err != nil {
		fmt.Println("Error Marshal JSON data: ", err)
	}

	err = ioutil.WriteFile(filename, file, 0644)

	if err != nil {
		fmt.Println("Error saving file to file system: ", err)
	} else {
		fmt.Println("Saved rego evaluation result to file system: ", filename)
	}

}
