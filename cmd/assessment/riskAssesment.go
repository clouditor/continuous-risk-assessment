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

	// Filename for IaC template
	iacTemplateOutputFilename string = "resources/outputs/arm_template.json"

	// Filename for ontology resource template
	ontologyResourceTemplateOutputFilename string = "resources/outputs/ontology_resource_template.json"

	// Filenames for the threat assessment
	threatProfileOntologyDir      string = "resources/threatprofiles/use_case_policy_ontology.rego"
	threatProfileDir              string = "resources/threatprofiles/use_case_policy.rego"
	cwCloudOutputFilename    string = "resources/outputs/cw_cloud.json"
	cwOntologyOutputFilename string = "resources/outputs/cw_ontology.json"

	// Filenames for the mapping of all applicable configuration weaknesses (CW) per asset
	reconstructAttackTreesProfileDir string = "resources/reconstruction/"
	cwPerAssetOutputFilename         string = "resources/outputs/cw_per_asset.json"
	cwPerAssetOntologyOutputFilename string = "resources/outputs/cw_per_asset_ontology.json" //TODO(garuppel): Do we need that?

	// Filenames for risk score calculation
	threatLevelsProfileDir          string = "resources/threatlevels/"
	riskScoreCloudOutputFilename    string = "resources/outputs/risk_scores_cloud.json"
	riskScoreOntologyOutputFilename string = "resources/outputs/risk_scores_ontology.json"
)

type ResultOntology struct {
	Result []ontology.IsCloudResource `json:"result"`
}

func init() {
	cobra.OnInitialize(initConfig)

	AssessmentCmd.Flags().String(discovery.SubscriptionIDFlag, "", "Subscription ID")
	AssessmentCmd.Flags().String(discovery.ResourceGroupFlag, "", "Resource Group")
	AssessmentCmd.Flags().String(discovery.AppTenantIDFlag, "", "Tenant ID of the Azure App")
	AssessmentCmd.Flags().String(discovery.AppClientIDFlag, "", "Client ID of the Azure App")
	AssessmentCmd.Flags().String(discovery.AppClientSecretFlag, "", "Client secret of the Azure App")

	viper.BindPFlag(discovery.SubscriptionIDFlag, AssessmentCmd.Flags().Lookup(discovery.SubscriptionIDFlag))
	viper.BindPFlag(discovery.ResourceGroupFlag, AssessmentCmd.Flags().Lookup(discovery.ResourceGroupFlag))
	viper.BindPFlag(discovery.AppTenantIDFlag, AssessmentCmd.Flags().Lookup(discovery.AppTenantIDFlag))
	viper.BindPFlag(discovery.AppClientIDFlag, AssessmentCmd.Flags().Lookup(discovery.AppClientIDFlag))
	viper.BindPFlag(discovery.AppClientSecretFlag, AssessmentCmd.Flags().Lookup(discovery.AppClientSecretFlag))

	AssessmentCmd.Flags().StringP("templatePath", "t", "", "IaC template path (currently only ARM templates are usable)")
	AssessmentCmd.Flags().StringP("ontologyPath", "o", "", "Ontology template path")
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

func doCmd(cmd *cobra.Command, args []string) (err error) {
	var (
		iacTemplateResult      interface{}
		ontologyTemplateResult interface{}
	)

	if viper.GetString(discovery.SubscriptionIDFlag) == "" {
		return errors.New("subscription ID is not set")
	}

	log.Info("Discovering...")
	iacTemplatePath, _ := cmd.Flags().GetString("templatePath")
	ontologyTemplatePath, _ := cmd.Flags().GetString("ontologyPath")

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

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

	// TODO merge the two risk assessment methods: what should be merged?
	// Risk Assessment based on IaC Template
	log.Info("Risk Assesment based on IaC Template ...")
	err = riskAssessmentIacTemplate(iacTemplateResult)
	if err != nil {
		return fmt.Errorf("risk assessment of iac template failed: %w", err)
	}

	// Risk Assessment based on Ontology Template
	log.Info("Risk Assesment based on Ontology Template ...")

	err = riskAssessmentOntologyTemplate(ontologyTemplateResult)
	if err != nil {
		return fmt.Errorf("risk assessment of ontology template failed: %w", err)
	}

	return nil
}

// AssessmentCmd exported for main.
var AssessmentCmd = &cobra.Command{
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

		filepath := getFilepathDate(iacTemplateOutputFilename)

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

		filepath := getFilepathDate(ontologyResourceTemplateOutputFilename)

		if err = saveToFilesystem(filepath, ontologyTemplateResult); err != nil {
			return nil, err
		}
	}

	return ontologyTemplateResult, nil
}


// TODO Can we merge this and the following method? riskAssessmentIaCTemplate/riskAssessmentOntologyTemplate
func riskAssessmentIacTemplate(iacTemplateResult interface{}) error {
	// Identify threats
	identifiedThreats := assessment.IdentifyThreats(threatProfileDir, iacTemplateResult)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	err := saveToFilesystem(cwCloudOutputFilename, identifiedThreats)
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

func riskAssessmentOntologyTemplate(ontologyTemplateResult interface{}) error {
	// Identify threats
	identifiedThreats := assessment.IdentifyThreats(threatProfileOntologyDir, ontologyTemplateResult)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	err := saveToFilesystem(cwOntologyOutputFilename, identifiedThreats)
	if err != nil {
		return fmt.Errorf("saving threats to filesystem failed: %w", err)
	}

	// Reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction := assessment.CwReconstruction(reconstructAttackTreesProfileDir, identifiedThreats)

	if attacktreeReconstruction == nil {
		log.Info("Attack tree reconstruction result is nil.")
	}

	err = saveToFilesystem(cwPerAssetOntologyOutputFilename, attacktreeReconstruction)
	if err != nil {
		return fmt.Errorf("saving  to filesystem  momentary configuration weaknesses based on the ontology failed: %w", err)
	}

	// Calculate risk scores per asset/protection goal
	threatLevels := assessment.CalculateRiskScores(threatLevelsProfileDir, identifiedThreats)

	if threatLevels == nil {
		log.Info("Identifying threat level result is nil.")
	}

	err = saveToFilesystem(riskScoreOntologyOutputFilename, threatLevels)
	if err != nil {
		return fmt.Errorf("saving risk scores to filesystem failed: %w", err)
	}

	return nil
}
