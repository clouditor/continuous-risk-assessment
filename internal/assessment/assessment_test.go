package assessment_test

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"testing"

	"clouditor.io/riskAssessment/cmd/assessment"
	ass_internal "clouditor.io/riskAssessment/internal/assessment"
	log "github.com/sirupsen/logrus"
)

type IaC struct {
	Template Template `json:"template"`
}
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

// type Property struct {
// 	Access string `json:"access"`
// }

type Property struct {
	SecurityRules []SecurityRule `json:"securityRules"`
}
type SecurityRule struct {
	Name               string               `json:"name"`
	SecurityProperties []SecurityProperties `json:"securityProperties"`
}
type SecurityProperties struct {
	Access string `json:"access"`
}

// func generateTemplate(amount int) {
// 	parameter := Parameter{
// 		DefaultValue: "name",
// 		Type:         "String",
// 	}
// 	property := Property{
// 		Access: "allow",
// 	}
// 	resource := Resource{
// 		APIVersion: "2020-05-01",
// 		Location:   "westeurope",
// 		Name:       "name",
// 		Properties: property,
// 	}
// 	template := Template{
// 		Schema:         "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
// 		ContentVersion: "1.0.0.0",
// 		Variables:      "",
// 		Parameters:     []Parameter{parameter},
// 		Resources:      []Resource{resource},
// 	}
// 	iac := IaC{
// 		Template: template,
// 	}

// 	// add further resources
// 	i := 1
// 	for i < amount {
// 		template.Resources = append(template.Resources, resource)
// 		i += 1
// 	}

// 	iacenc, err := json.Marshal(iac)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	ioutil.WriteFile("testfiles/template.json", []byte(iacenc), os.ModePerm)
// }

func generateComplicatedTemplate(amount int) {
	parameter := Parameter{
		DefaultValue: "name",
		Type:         "String",
	}
	securityProperties := SecurityProperties{
		Access: "allow",
	}
	securityRule := SecurityRule{
		Name:               "name",
		SecurityProperties: []SecurityProperties{securityProperties},
	}
	property := Property{
		SecurityRules: []SecurityRule{securityRule},
		// Access: "allow",
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
	iac := IaC{
		Template: template,
	}

	// add further resources
	i := 1
	for i < amount {
		iac.Template.Resources = append(iac.Template.Resources, resource)
		i += 1
	}

	iacenc, err := json.Marshal(iac)
	if err != nil {
		log.Fatal(err)
	}
	ioutil.WriteFile("testfiles/template.json", []byte(iacenc), os.ModePerm)
}

func generateThreatProfile(amount int) {
	tp := `package threatprofile

	storageaccount_confidentiality_accessPublicly {
		input.template.resources[i].properties.securityRules.securityProperties[_].access == "allow"
	}
	`
	// input.template.resources[i].properties.access == "allow"
	i := 0
	for i < amount {
		tp += "\n" + `storageaccount_confidentiality_accessPublicly` + strconv.Itoa(i) + `{
			input.template.resources[i].properties.securityRules.securityProperties[_].access == "allow"
		}`
		i++
	}
	ioutil.WriteFile("testfiles/policy.rego", []byte(tp), os.ModePerm)
}

// func BenchmarkRegoEvaluation(b *testing.B) {
// 	generateTemplate(16384)
// 	generateThreatProfile(16384)

// 	for i := 0; i < b.N; i++ {
// 		ass_internal.IdentifyThreatsFromTemplate("testfiles/", "testfiles/template.json")
// 	}
// }

func regoEvaluation(tempAmount int, tpAmount int) {
	// generateTemplate(tempAmount)
	generateComplicatedTemplate(tempAmount)
	generateThreatProfile(tpAmount)

	ass_internal.IdentifyThreats("testfiles/", "testfiles/template.json")
}

func BenchmarkRegoEvaluation(b *testing.B) {
	for k := 0.; k <= 2; k++ {
		n := int(math.Pow(2, k))
		generateComplicatedTemplate(n)
		// generateTemplate(n)
		for l := 0.; l <= 2; l++ {
			m := int(math.Pow(2, l))
			generateThreatProfile(m)
			b.Run(fmt.Sprintf("%d/%d", n, m), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					ass_internal.IdentifyThreats("internal/assessment/testfiles/", "internal/assessment/testfiles/template.json")
				}
			})
		}
	}
}

// Tests the whole risk assessment process
func TestRiskAssessment(t *testing.T) {
	assessment.AssessmentCmd.Execute()
}

func init() {
	os.Chdir("../../")
}
