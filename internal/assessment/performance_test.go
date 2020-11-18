package assessment

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"
)

type Template struct {
	Schema         string      `json:"$schema"`
	ContentVersion string      `json:"contentVersion"`
	Parameters     []Parameter `json:"parameters"`
	Variables      string      `json:"variables"`
	Resources      []Resource  `json:"resources"`
}
type Parameter struct {
	DefaultValue string `json:"defaultValue"`
	Type         string `json:"type"`
}
type Resource struct {
	APIVersion string     `json:"apiVersion"`
	Location   string     `json:"location"`
	Name       string     `json:"name"`
	Properties []Property `json:"properties"`
}
type Property struct {
	Access string `json:"access"`
}

func generateMinimalTemplate() Template {
	parameter := Parameter{
		DefaultValue: "name",
		Type:         "String",
	}
	property := Property{
		Access: "allow",
	}
	resource := Resource{
		APIVersion: "2020-05-01",
		Location:   "westeurope",
		Name:       "name",
		Properties: []Property{property},
	}
	template := Template{
		Schema:         "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
		ContentVersion: "1.0.0.0",
		Variables:      "",
		Parameters:     []Parameter{parameter},
		Resources:      []Resource{resource},
	}
	// return json.Marshal(template)
	return template
}

var threatProfile = `package example.threats

storageaccount_confidentiality_accessPublicly[storageaccount_names] {
	input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
	input.template.resources[i].properties.allowBlobPublicAccess == true

	storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}
get_default_names(resource_names) = resource_default_names{    
	resource_default_names := input.template.parameters[i]["defaultValue"]
	resource_names == i
}`

// TODO is there some caching that can be deactivated?
func TestBigTemplatePerformance(t *testing.T) {
	template := generateMinimalTemplate()

	// add 1, 2, 4, 8, ... resources to the template
	property := Property{
		Access: "deny",
	}
	resource := Resource{
		APIVersion: "2020-05-01",
		Location:   "westeurope",
		Name:       "name",
		Properties: []Property{property},
	}

	// add further resources
	template.Resources = append(template.Resources, resource)

	templateenc, err := json.Marshal(template)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(templateenc))

	// write template to file
	ioutil.WriteFile("testfiles/bigtemplate.json", templateenc, os.ModePerm)
	// write rego to file
	ioutil.WriteFile("testfiles/smallpolicy.rego", []byte(threatProfile), os.ModePerm)

	// call evaluation func
	identifiedThreats := IdentifyThreatsFromTemplate("testfiles/", "testfiles/bigtemplate.json")

	if identifiedThreats == nil {
		fmt.Println("Nil threats identified")
	}
	// cleanup
	// err = os.Remove("bigtemplate.json")
	// err = os.Remove("smallpolicy.rego")
	// if err != nil {
	// 	fmt.Println(err)
	// }
}

func TestBigThreatProfilePerformance(t *testing.T) {
	// create minimal template, create minimal threat profile
	// template := generateMinimalTemplate()
	additionalPolicy := `storageaccount_confidentiality_accessPublicly[storageaccount_names] {
		input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
		input.template.resources[i].properties.allowBlobPublicAccess == true

		storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
	}`
	// add 2, 4, 8, ... threat profiles
	i := 0
	tp := threatProfile
	for i < 2 {
		tp += "\n" + strconv.Itoa(i) + additionalPolicy
		i += 1
	}
	fmt.Println(tp)
	// TODO evaluate template against threatprofile
}