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

	// Filenames for threat identification
	threatProfileOntologyDir      string = "resources/threatprofiles/use_case_policy_ontology.rego"
	threatProfileDir              string = "resources/threatprofiles/use_case_policy.rego"
	threatsOntologyOutputFilename string = "resources/outputs/threats_ontology.json"
	threatsOutputFilename         string = "resources/outputs/threats.json"

	// Filenames for attack tree reconstruction
	reconstructAttackTreesProfileDir               string = "resources/reconstruction/"
	attackTreeReconstructionOutputFilename         string = "resources/outputs/momentary_attacktree.json"
	attackTreeReconstructionOntologyOutputFilename string = "resources/outputs/momentary_attacktree_ontology.json"

	// Filenames for risk score calculation
	riskScoreProfileDir             string = "resources/threatlevels/"
	riskScoreOutputFilename         string = "resources/outputs/threatlevels.json"
	riskScoreOntologyOutputFilename string = "resources/outputs/threatlevels_ontology.json"
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

	AssessmentCmd.Flags().StringP("path", "p", "", "IaC template path (currently only ARM templates are usable)")
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
	if viper.GetString(discovery.SubscriptionIDFlag) == "" {
		return errors.New("subscription ID is not set")
	}

	// Check pathes
	checkPathes()

	log.Info("Discovering...")
	templatePath, _ := cmd.Flags().GetString("path")

	// Not necessary if we are using the ontology-based template file instead of the IaC template
	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	// Discover IaC template
	var iacTemplate interface{}
	// var iacTemplate resources.GroupExportResult

	// Check if IaC template path is given
	if templatePath != "" {
		log.Info("Get IaC template from file system: ", templatePath)
		iacTemplate = readFromFilesystem(templatePath)
	} else {
		log.Info("Discover IaC template from Azure.")
		iacTemplate, err = app.DiscoverIacTemplate()
		if err != nil {
			return err
		}

		filepath := getFilepathDate(iacTemplateOutputFilename)

		if err = saveToFilesystem(filepath, iacTemplate); err != nil {
			return err
		}
	}

	// Create ontology-based resource template from IaC template
	log.Info("Create ontology-based resource template from IaC template")
	template, ok := iacTemplate.(resources.GroupExportResult).Template.(map[string]interface{})
	if !ok {
		return fmt.Errorf("IaC template type convertion failed")
	}

	ontologyTemplate, err := app.CreateOntologyTemplate(template)
	if err != nil {
		return fmt.Errorf("creating ontology template failed: %w", err)
	}

	ontologyTemplateResult := ResultOntology{
		Result: ontologyTemplate,
	}

	filepath := getFilepathDate(ontologyResourceTemplateOutputFilename)

	if err = saveToFilesystem(filepath, ontologyTemplateResult); err != nil {
		return err
	}

	// Risk Assessment based on IaC Template
	log.Info("Risk Assesment based on IaC Template ...")

	// Identify threats
	identifiedThreats := assessment.IdentifyThreatsFromIacTemplate(threatProfileDir, iacTemplate)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	saveToFilesystem(threatsOutputFilename, identifiedThreats)

	// Reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction := assessment.ReconstructAttackTrees(reconstructAttackTreesProfileDir, identifiedThreats)

	if attacktreeReconstruction == nil {
		log.Info("Attack tree reconstruction result is nil.")
	}

	saveToFilesystem(attackTreeReconstructionOutputFilename, attacktreeReconstruction)

	// Calculate risk scores per asset/protection goal
	threatLevels := assessment.CalculateRiskScores(riskScoreProfileDir, identifiedThreats)

	if threatLevels == nil {
		log.Info("Identifying threat level result is nil.")
	}

	saveToFilesystem(riskScoreOutputFilename, threatLevels)

	// Risk Assessment based on Ontology Template
	log.Info("Risk Assesment based on Ontology Template ...")

	iacTemplate = ontologyTemplateResult
	// Identify threats
	identifiedThreats = assessment.IdentifyThreatsFromIacTemplate(threatProfileOntologyDir, iacTemplate)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	saveToFilesystem(threatsOntologyOutputFilename, identifiedThreats)

	// Reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction = assessment.ReconstructAttackTrees(reconstructAttackTreesProfileDir, identifiedThreats)

	if attacktreeReconstruction == nil {
		log.Info("Attack tree reconstruction result is nil.")
	}

	saveToFilesystem(attackTreeReconstructionOntologyOutputFilename, attacktreeReconstruction)

	// Calculate risk scores per asset/protection goal
	threatLevels = assessment.CalculateRiskScores(riskScoreProfileDir, identifiedThreats)

	if threatLevels == nil {
		log.Info("Identifying threat level result is nil.")
	}

	saveToFilesystem(riskScoreOntologyOutputFilename, threatLevels)

	return nil
}

// AssessmentCmd exported for main.
var AssessmentCmd = &cobra.Command{
	Use:   "riskAssessment",
	Short: "Continuous risk assessment for Azure",
	Long:  "riskAssessment is a automated continuous risk assessment for the customer cloud environment and consists of the Azure Cloud Discovery to obtain the IaC template and the Assessment for identifying threats, calculating risk scores and reconstructing attack trees. Currently, the assessment is only available for the Azure Cloud.",
	RunE:  doCmd,
}

// TODO fix, depending on the start path, the pathes are not correct. For now it is checked if the program starts in cmd folder, otherwise it has to start from root folder
func checkPathes() {
	pathcwd, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Println(pathcwd)
	pathcwdSplit := strings.Split(pathcwd, "/")

	if (pathcwdSplit[len(pathcwdSplit)-1]) == "cmd" {
		iacTemplateOutputFilename = "../" + iacTemplateOutputFilename
		threatProfileDir = "../" + threatProfileDir
		threatsOutputFilename = "../" + threatsOutputFilename
		reconstructAttackTreesProfileDir = "../" + reconstructAttackTreesProfileDir
		attackTreeReconstructionOutputFilename = "../" + attackTreeReconstructionOutputFilename
		riskScoreProfileDir = "../" + riskScoreProfileDir
		riskScoreOutputFilename = "../" + riskScoreOutputFilename
		ontologyResourceTemplateOutputFilename = "../" + ontologyResourceTemplateOutputFilename
		threatProfileOntologyDir = "../" + threatProfileOntologyDir
		threatsOntologyOutputFilename = "../" + threatsOntologyOutputFilename
		attackTreeReconstructionOntologyOutputFilename = "../" + attackTreeReconstructionOntologyOutputFilename
		riskScoreOntologyOutputFilename = "../" + riskScoreOntologyOutputFilename
	}
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
