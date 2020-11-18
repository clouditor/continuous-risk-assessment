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
	APIVersion string   `json:"apiVersion"`
	Location   string   `json:"location"`
	Name       string   `json:"name"`
	Properties Property `json:"properties"`
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
		Properties: property,
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

func generateBigTemplate() Template {
	template := generateMinimalTemplate()

	// add 1, 2, 4, 8, ... resources to the template
	property := Property{
		Access: "deny",
	}
	resource := Resource{
		APIVersion: "2020-05-01",
		Location:   "westeurope",
		Name:       "name",
		Properties: property,
	}

	// add further resources
	i := 0
	for i < 100 {
		template.Resources = append(template.Resources, resource)
		i += 1
	}
	return template
}

var threatProfile = `package threatprofile

storageaccount_confidentiality_accessPublicly {
	input.resources[i].properties.access == "allow"
}
`

// TODO is there some caching that can be deactivated?
func TestBigTemplatePerformance(t *testing.T) {
	template := generateBigTemplate()

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
	// identifiedThreats := IdentifyThreatsFromTemplate("../../resources/threatprofiles/testPolicy.rego", "testfiles/bigtemplate.json")
	fmt.Println(identifiedThreats)

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
	i := 0
	tp := threatProfile
	for i < 12000 {
		tp += "\n" + `storageaccount_confidentiality_accessPublicly` + strconv.Itoa(i) + `{
			input.resources[i].properties.access == "allow"
		}`
		i += 1
	}
	fmt.Println(tp)
	ioutil.WriteFile("testfiles/smallpolicy.rego", []byte(tp), os.ModePerm)

	// create template and write template to file
	template := generateBigTemplate() // generateMinimalTemplate()
	templateenc, err := json.Marshal(template)
	if err != nil {
		fmt.Println(err)
	}
	ioutil.WriteFile("testfiles/bigtemplate.json", templateenc, os.ModePerm)

	// evaluate template against threatprofile
	identifiedThreats := IdentifyThreatsFromTemplate("testfiles/", "testfiles/bigtemplate.json")
	// identifiedThreats := IdentifyThreatsFromTemplate("testfiles/", "../../resources/inputs/testTemplate.json")
	fmt.Println(identifiedThreats)

	if identifiedThreats == nil {
		fmt.Println("Nil threats identified")
	}
}
