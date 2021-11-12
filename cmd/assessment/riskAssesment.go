package assessment

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2019-05-01/resources"
	log "github.com/sirupsen/logrus"

	"clouditor.io/riskAssessment/internal/assessment"
	"clouditor.io/riskAssessment/internal/ontology"

	"clouditor.io/riskAssessment/internal/discovery"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const envPrefix = "CLOUDITOR"

var (

	// Filename for the IaC template
	iacOutputFilename = "resources/outputs/arm_template.json"

	// Filename for the ontology resource template
	ontologyOutputFilename = "resources/outputs/ontology_resource_template.json"

	// Filenames for the threat assessment
	threatIacProfileDir      = "resources/threatprofiles/use_case_policy.rego"
	threatOntologyProfileDir = "resources/threatprofiles/use_case_policy_ontology.rego"
	cwIacOutputFilename      = "resources/outputs/cw_iac.json"
	cwOntologyOutputFilename = "resources/outputs/cw_ontology.json"

	// Filenames for the mapping of all applicable configuration weaknesses (CW) per asset
	reconstructAttackTreesProfileDir = "resources/reconstruction/"
	cwPerAssetIacOutputFilename      = "resources/outputs/cw_per_asset_iac.json"
	cwPerAssetOntologyOutputFilename = "resources/outputs/cw_per_asset_ontology.json"

	// Filenames for risk score calculation
	threatLevelsProfileDir          = "resources/threatlevels/"
	riskScoreIacOutputFilename      = "resources/outputs/risk_scores_iac.json"
	riskScoreOntologyOutputFilename = "resources/outputs/risk_scores_ontology.json"
)

type ResultOntology struct {
	Result []ontology.IsCloudResource `json:"result"`
}

func init() {
	cobra.OnInitialize(initConfig)

	CmdAssessment.Flags().String(discovery.SubscriptionIDFlag, "", "Subscription ID")
	CmdAssessment.Flags().String(discovery.ResourceGroupFlag, "", "Resource Group")
	CmdAssessment.Flags().String(discovery.AppTenantIDFlag, "", "Tenant ID of the Azure App")
	CmdAssessment.Flags().String(discovery.AppClientIDFlag, "", "Client ID of the Azure App")
	CmdAssessment.Flags().String(discovery.AppClientSecretFlag, "", "Client secret of the Azure App")

	_ = viper.BindPFlag(discovery.SubscriptionIDFlag, CmdAssessment.Flags().Lookup(discovery.SubscriptionIDFlag))
	_ = viper.BindPFlag(discovery.ResourceGroupFlag, CmdAssessment.Flags().Lookup(discovery.ResourceGroupFlag))
	_ = viper.BindPFlag(discovery.AppTenantIDFlag, CmdAssessment.Flags().Lookup(discovery.AppTenantIDFlag))
	_ = viper.BindPFlag(discovery.AppClientIDFlag, CmdAssessment.Flags().Lookup(discovery.AppClientIDFlag))
	_ = viper.BindPFlag(discovery.AppClientSecretFlag, CmdAssessment.Flags().Lookup(discovery.AppClientSecretFlag))

	CmdAssessment.Flags().StringP("templatePath", "t", "", "IaC template path (currently only ARM templates are usable)")
	CmdAssessment.Flags().StringP("ontologyPath", "o", "", "Ontology template path")
}

func initConfig() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix(envPrefix)
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		log.Errorf("Could not read config: %s", err)
	}
}

func doCmd(_ *cobra.Command, args []string) (err error) {
	var (
		iacTemplateResult      interface{}
		ontologyTemplateResult interface{}
		iacTemplatePath        string
		ontologyTemplatePath   string
	)

	if viper.GetString(discovery.SubscriptionIDFlag) == "" {
		return errors.New("subscription ID is not set")
	}

	log.Info("Discovering...")
	iacTemplatePath = args[3]
	ontologyTemplatePath = args[1]

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	// TODO(garuppel): Do not return error, if one of both is getting an template
	// Get IaC template
	iacTemplateResult, err = getIacTemplate(app, iacTemplatePath)
	if err != nil {
		return fmt.Errorf("getting IaC template failed: %w", err)
	}

	// Get ontology template
	ontologyTemplateResult, err = getOntologyTemplate(app, ontologyTemplatePath, iacTemplateResult)
	if err != nil {
		return fmt.Errorf("getting IaC template failed: %w", err)
	}

	// Risk Assessment based on IaC Template
	log.Info("Risk Assessment based on IaC Template ...")
	err = riskAssessment(iacTemplateResult, threatIacProfileDir, cwIacOutputFilename, cwPerAssetIacOutputFilename, riskScoreIacOutputFilename)
	if err != nil {
		return fmt.Errorf("risk assessment of iac template failed: %w", err)
	}

	// Risk Assessment based on Ontology Template
	log.Info("Risk Assessment based on Ontology Template ...")
	err = riskAssessment(ontologyTemplateResult, threatOntologyProfileDir, cwOntologyOutputFilename, cwPerAssetOntologyOutputFilename, riskScoreOntologyOutputFilename)
	if err != nil {
		return fmt.Errorf("risk assessment of ontology template failed: %w", err)
	}

	return nil
}

// CmdAssessment exported for main.
var CmdAssessment = &cobra.Command{
	Use:   "riskAssessment",
	Short: "Continuous risk assessment for Azure",
	Long:  "riskAssessment is a automated continuous risk assessment for the customer cloud environment and consists of the Azure Cloud Discovery to obtain the IaC template and the Assessment for identifying threats, calculating risk scores and reconstructing attack trees. Currently, the assessment is only available for the Azure Cloud.",
	RunE:  doCmd,
}

// getFilepathDate adds current date to the filename
func getFilepathDate(iacTemplateOutputFilename string) string {
	currentTime := time.Now()

	stringSplit := strings.Split(iacTemplateOutputFilename, "/")
	path := strings.Join(stringSplit[:len(stringSplit)-1], "/") + "/" + currentTime.Format("2006-02-01") + "_" + strings.Join(stringSplit[len(stringSplit)-1:], "")

	return path
}

// readFromFilesystem reads file from path.
func readFromFilesystem(path string) interface{} {

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

// saveToFilesystem saves data to filesystem.
func saveToFilesystem(path string, data interface{}) (err error) {
	file, err := json.MarshalIndent(data, "", " ")

	if err != nil {
		log.Fatal("Error Marshal JSON data: ", err)
		return err
	}

	err = ioutil.WriteFile(path, file, 0644)

	if err != nil {
		log.Fatal("Error saving file to file system: ", err)
		return err
	}

	log.Info("Saved data to ", path)

	return nil
}

func getIacTemplate(app *discovery.App, iacTemplatePath string) (interface{}, error) {

	var (
		iacTemplate interface{}
		err         error
	)

	// Check if filepath is available
	if iacTemplatePath != "" {
		log.Info("Get IaC template from file system: ", iacTemplatePath)
		iacTemplate = readFromFilesystem(iacTemplatePath)
	} else {
		log.Info("Discover IaC template from Azure.")
		iacTemplate, err = app.DiscoverIacTemplate()
		if err != nil {
			return nil, err
		}

		filepath := getFilepathDate(iacOutputFilename)

		if err = saveToFilesystem(filepath, iacTemplate); err != nil {
			return nil, err
		}
	}

	return iacTemplate, nil
}

func getOntologyTemplate(app *discovery.App, ontologyTemplatePath string, iacTemplate interface{}) (interface{}, error) {

	var (
		ontologyTemplateResult interface{}
		template               map[string]interface{}
		ok                     bool
	)

	// Check if filepath is available
	if ontologyTemplatePath != "" {
		log.Info("Get ontology template from file system: ", ontologyTemplatePath)
		ontologyTemplateResult = readFromFilesystem(ontologyTemplatePath)
	} else {

		// Create ontology-based resource template from IaC template
		log.Info("Create ontology-based resource template from IaC template")

		// Check if iacTemplate is of type interface{} or resources.GroupExportResult. If iacTemplate is discovered from Azure it is of type resources.GroupExportResult, otherwise it it is read from filesystem it is of type interface{}
		switch iacTemplate.(type) {
		case map[string]interface{}:
			iacResult, ok := iacTemplate.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("IaC template type convertion failed")
			}
			template = iacResult["template"].(map[string]interface{})

		case interface{}:
			template, ok = iacTemplate.(resources.GroupExportResult).Template.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("IaC template type convertion failed")
			}

		}

		ontologyTemplate, err := app.CreateOntologyTemplate(template)
		if err != nil {
			return nil, fmt.Errorf("creating ontology template failed: %w", err)
		}

		ontologyTemplateResult = ResultOntology{
			Result: ontologyTemplate,
		}

		filepath := getFilepathDate(ontologyOutputFilename)

		if err = saveToFilesystem(filepath, ontologyTemplateResult); err != nil {
			return nil, err
		}
	}

	return ontologyTemplateResult, nil
}

func riskAssessment(iacTemplateResult interface{}, threatProfileDir, cwOutputFilename, cwPerAssetOutputFilename, riskScoreCloudOutputFilename string) error {
	// Identify threats
	identifiedThreats := assessment.IdentifyThreats(threatProfileDir, iacTemplateResult)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	err := saveToFilesystem(cwOutputFilename, identifiedThreats)
	if err != nil {
		return fmt.Errorf("saving threats to filesystem failed: %w", err)
	}

	// Reconstruct attack paths, i.e. identify all attack paths per asset
	cwReconstruction := assessment.CwReconstruction(reconstructAttackTreesProfileDir, identifiedThreats)

	if cwReconstruction == nil {
		log.Info("Attack tree reconstruction result is nil.")
	}

	err = saveToFilesystem(cwPerAssetOutputFilename, cwReconstruction)
	if err != nil {
		return fmt.Errorf("saving attack tree reconstrunction to filesystem failed: %w", err)
	}

	// Calculate risk scores per asset/protection goal
	threatLevels := assessment.CalculateRiskScores(threatLevelsProfileDir, identifiedThreats)

	if threatLevels == nil {
		log.Info("Identifying threat level result is nil.")
	}

	err = saveToFilesystem(riskScoreCloudOutputFilename, threatLevels)
	if err != nil {
		return fmt.Errorf("saving risk score to filesystem failed: %w", err)
	}
	return nil
}
