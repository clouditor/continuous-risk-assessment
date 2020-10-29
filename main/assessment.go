package main

import (
	"context"
	"fmt"

	"github.com/open-policy-agent/opa/rego"
)

func evaluateExamplePolicy() {

	module := `
package example.authz

default allow = false

allow {
    some id
    input.method = "GET"
    input.path = ["salary", id]
    input.subject.user = id
}

allow {
    is_admin
}

is_admin {
    input.subject.groups[_] = "admin"
}
`
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
