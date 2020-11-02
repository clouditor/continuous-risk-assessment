package assessment

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/open-policy-agent/opa/rego"
)

func EvaluatePolicy() {

	ctx := context.TODO()
	r, err := rego.New(
		rego.Query("x = data.threats"),
		rego.Load([]string{"./resources/threat_profiles/"}, nil),
	).PrepareForEval(ctx)

	input := jsonFileInput("./resources/inputs/testTemplate.json")

	results, err := r.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		log.Fatal(err)
	}

	for index, element := range results {
		fmt.Println(element)
		if err != nil {
			// Handle evaluation error.
		} else if len(results) == 0 {
			// Handle undefined result.
		} else if result, ok := results[index].Bindings["x"].(bool); !ok {
			fmt.Println(result)
		} else {
			// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
		}
	}
}

func EvaluateExamplePolicy(policyPath string) {

	// get policy
	content, err := ioutil.ReadFile(policyPath)
	module := string(content)
	ctx := context.TODO()
	query, err := rego.New(
		rego.Query("x = data.example.authz.allow"),
		rego.Module("example.rego", module),
	).PrepareForEval(ctx)

	if err != nil {
		// Handle error.
	}

	input := map[string]interface{}{
		"method": "GET",
		"path":   []interface{}{"salary", "bob"},
		"subject": map[string]interface{}{
			"user":   "bob",
			"groups": []interface{}{"sales", "marketing"},
		},
	}

	results, err := query.Eval(ctx, rego.EvalInput(input))

	for index, element := range results {
		fmt.Println(element)
		if err != nil {
			// Handle evaluation error.
		} else if len(results) == 0 {
			// Handle undefined result.
		} else if result, ok := results[index].Bindings["x"].(bool); !ok {
			fmt.Println(result)
		} else {
			// Handle result/decision.
			// fmt.Printf("%+v", results) => [{Expressions:[true] Bindings:map[x:true]}]
		}
	}

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
