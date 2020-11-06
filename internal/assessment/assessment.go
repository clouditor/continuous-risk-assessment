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

func EvaluatePolicy(threatprofile_dir string) (results rego.ResultSet) {

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.minimal"),
		rego.Load([]string{threatprofile_dir}, nil),
	).PrepareForEval(ctx)

	input := jsonFileInput("resources/inputs/minimaltemplate.json")

	results, err = r.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	pretty.Print(results)

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

// SaveToJsonFile saves rego binding results to file system.
func SaveToJSONFile(filename string, data rego.ResultSet) {
	file, _ := json.MarshalIndent(data, "", " ")

	err := ioutil.WriteFile(filename, file, 0644)

	if err != nil {
		fmt.Println("Error saving file to file system: ", err)
	} else {
		fmt.Printf("Saved rego evaluation result to file system: %s", filename)
	}

}

func Reconstruct_attacktrees(data rego.ResultSet) (attacktrees rego.ResultSet) {
	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.reconstruction"),
		rego.Load([]string{"./resources/reconstruction/"}, nil),
	).PrepareForEval(ctx)

	attacktrees, err = r.Eval(ctx, rego.EvalInput(data))
	if err != nil {
		log.Fatal(err)
	}

	pretty.Print(attacktrees)

	return attacktrees
}

func Identify_highest_threat_level(evaluationResult rego.ResultSet) (threatlevels rego.ResultSet) {

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("data.threatlevels"),
		rego.Load([]string{"./resources/threatlevels/"}, nil),
	).PrepareForEval(ctx)

	threatlevels, err = r.Eval(ctx, rego.EvalInput(evaluationResult))
	if err != nil {
		log.Fatal(err)
	}

	pretty.Print(threatlevels)

	return threatlevels
}
