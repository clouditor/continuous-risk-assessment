package assessment

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"

	"clouditor.io/riskAssessment/internal/assessment"

	"clouditor.io/riskAssessment/internal/discovery"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	envPrefix = "CLOUDITOR"

	// Filename for IaC template
	iacTemplateOutputFilename string = "./resources/outputs/arm_template.json"

	// Filenames for threat identification
	threatProfileDir      string = "./resources/threatprofiles/use_case_policy.rego"
	threatsOutputFilename string = "./resources/outputs/threats.json"

	// Filenames for attack tree reconstruction
	reconstructAttackTreesProfileDir       string = "./resources/reconstruction/"
	attackTreeReconstructionOutputFilename string = "./resources/outputs/momentary_attacktree.json"

	// Filenames for risk score calculation
	riskScoreProfileDir     string = "./resources/threatlevels/"
	riskScoreOutputFilename string = "./resources/outputs/threatlevels.json"
)

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
		return errors.New("Subscription ID is not set")
	}

	log.Info("Discovering...")
	templatePath, _ := cmd.Flags().GetString("path")

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	// Discover IaC template
	var iacTemplate interface{}

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

	// Risk Assessment
	log.Info("Risk Assesment...")

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
