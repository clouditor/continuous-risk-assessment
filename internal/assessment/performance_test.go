package assessment

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"strconv"
	"testing"

	disc "clouditor.io/riskAssessment/cmd/discovery"
	"github.com/smartystreets/goconvey/convey"
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
type Property struct {
	Access string `json:"access"`
}

func generateTemplate(amount int) {
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
	iac := IaC{
		Template: template,
	}

	// add further resources
	i := 1
	for i < amount {
		template.Resources = append(template.Resources, resource)
		i++
	}

	iacenc, err := json.Marshal(iac)
	if err != nil {
		fmt.Println(err)
	}
	ioutil.WriteFile("testfiles/template.json", []byte(iacenc), os.ModePerm)
}

func generateThreatProfile(amount int) {
	tp := `package threatprofile

	storageaccount_confidentiality_accessPublicly {
		input.template.resources[i].properties.access == "allow"
	}
	`
	i := 0
	for i < amount {
		tp += "\n" + `storageaccount_confidentiality_accessPublicly` + strconv.Itoa(i) + `{
			input.template.resources[i].properties.access == "allow"
		}`
		i++
	}
	ioutil.WriteFile("testfiles/policy.rego", []byte(tp), os.ModePerm)
}

// func BenchmarkRegoEvaluation(b *testing.B) {
// 	generateTemplate(16384)
// 	generateThreatProfile(16384)

// 	for i := 0; i < b.N; i++ {
// 		IdentifyThreatsFromTemplate("testfiles/", "testfiles/template.json")
// 	}
// }

func regoEvaluation(tempAmount int, tpAmount int) {
	generateTemplate(tempAmount)
	generateThreatProfile(tpAmount)

	IdentifyThreatsFromTemplate("testfiles/", "testfiles/template.json")
}

func BenchmarkRegoEvaluation(b *testing.B) {
	for k := 0.; k <= 10; k++ {
		n := int(math.Pow(2, k))
		generateTemplate(n)
		for l := 0.; l <= 10; l++ {
			m := int(math.Pow(2, l))
			generateThreatProfile(m)
			b.Run(fmt.Sprintf("%d/%d", n, m), func(b *testing.B) {
				for i := 0; i < b.N; i++ {
					IdentifyThreatsFromTemplate("testfiles/", "testfiles/template.json")
				}
			})
		}
	}
}

func TestCompleteModule2(t *testing.T) {
	// discovery + assessment

	// //Config
	// viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	// viper.SetEnvPrefix("CLOUDITOR")
	// viper.AutomaticEnv()
	// viper.SetConfigName("config")
	// viper.SetConfigType("yaml")
	// viper.AddConfigPath(".")

	// var err error

	// err = viper.ReadInConfig()
	// if err != nil {
	// 	fmt.Printf("Could not read config: %s", err)
	// }

	// // Declare var
	// viper.BindPFlag(discovery.SubscriptionIDFlag, discoverCmd.Flags().Lookup(discovery.SubscriptionIDFlag))
	// viper.BindPFlag(discovery.ResourceGroupFlag, discoverCmd.Flags().Lookup(discovery.ResourceGroupFlag))
	// viper.BindPFlag(discovery.AppTenantIDFlag, discoverCmd.Flags().Lookup(discovery.AppTenantIDFlag))
	// viper.BindPFlag(discovery.AppClientIDFlag, discoverCmd.Flags().Lookup(discovery.AppClientIDFlag))
	// viper.BindPFlag(discovery.AppClientSecretFlag, discoverCmd.Flags().Lookup(discovery.AppClientSecretFlag))

	// disc.InitConfig()
	// disc.Init()
	convey.Convey("", t, func() {
		args := []string{"discover"}
		disc.DiscoverCmd.SetArgs(args)
		disc.DiscoverCmd.Execute()

	})

	// app := &discovery.App{}
	// if err = app.AuthorizeAzure(); err != nil {
	// 	fmt.Println("Authorization error: ", err)
	// }

	// armTemplate, err := app.ExportArmTemplate()
	// if err != nil {
	// 	fmt.Println("ARM template export error: ", err)
	// }

	// fmt.Println("armTemplate: ", armTemplate)

	// I've copied the func IdentifyThreatsFromTemplate to IdentifyThreatsFromARMTemplate,
	// because the original function IdentifyThreatsFromTemplate became the path to the
	// template file. Now the func IdentifyThreatsFromARMTemplate gets directly the template object
	// 'armTemplate'.
	// IdentifyThreatsFromARMTemplate does not work and I assume that the object 'armTemplate' is
	// not the same format as the imported ARM tempate from the filesystem.
	// IdentifyThreatsFromARMTemplate("resources/threatprofiles/use_case_policy.rego", armTemplate)

	// fmt.Println("threats: ", threats)

}
