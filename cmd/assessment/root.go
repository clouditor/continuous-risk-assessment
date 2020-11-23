package assessment

import (
	"errors"
	"fmt"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"

	"clouditor.io/riskAssessment/internal/assessment"

	"clouditor.io/riskAssessment/internal/discovery"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const (
	envPrefix = "CLOUDITOR"
)

// const for running risk assessment
// const (
// 	// File names for evaluation
// 	threatProfileDataInputFileName string = "./resources/inputs/use_case_template.json"
// 	threatProfileDir               string = "./resources/threatprofiles/use_case_policy.rego"
// 	threatProfileOutputFileName    string = "./resources/outputs/threats.json"

// 	// File names for attack tree reconstruction
// 	reconstructAttackTreesProfileDir       string = "./resources/reconstruction/"
// 	attackTreeReconstructionOutputFileName string = "./resources/outputs/momentary_attacktree.json"

// 	// File names for threat level evaluation
// 	threatLevelsProfileDir     string = "./resources/threatlevels/"
// 	threatLevelsOutputFileName string = "./resources/outputs/threatlevels.json"
// )

// const for running test
const (
	// File names for evaluation
	threatProfileDataInputFileName string = "./resources/inputs/use_case_template.json"
	threatProfileDir               string = "./resources/threatprofiles/use_case_policy.rego"
	threatProfileOutputFileName    string = "./resources/outputs/threats.json"

	// File names for attack tree reconstruction
	reconstructAttackTreesProfileDir       string = "./resources/reconstruction/"
	attackTreeReconstructionOutputFileName string = "./resources/outputs/momentary_attacktree.json"

	// File names for threat level evaluation
	threatLevelsProfileDir     string = "./resources/threatlevels/"
	threatLevelsOutputFileName string = "./resources/outputs/threatlevels.json"
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

	path, err := os.Getwd()
	if err != nil {
		log.Println(err)
	}
	fmt.Println(path) // for example /home/user

	log.Info("Discovering...")

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	// armTemplate, err := app.ExportArmTemplate()
	// // _, err = app.ExportArmTemplate()
	// if err != nil {
	// 	return err
	// }

	// evaluate template against threat profiles
	identifiedThreats := assessment.IdentifyThreatsFromTemplate(threatProfileDir, threatProfileDataInputFileName)
	// identifiedThreats := assessment.IdentifyThreatsFromARMTemplate(threatProfileDir, armTemplate)

	if identifiedThreats == nil {
		return os.ErrInvalid
	}

	assessment.SaveToFilesystem(threatProfileOutputFileName, identifiedThreats)

	// reconstruct attack paths, i.e. identify all attack paths per asset
	attacktreeReconstruction := assessment.ReconstructAttackTrees(reconstructAttackTreesProfileDir, identifiedThreats)

	if attacktreeReconstruction == nil {
		fmt.Println("Attack tree reconstruction result is nil.")
	}

	assessment.SaveToFilesystem(attackTreeReconstructionOutputFileName, attacktreeReconstruction)

	// calculate risk scores per asset/protection goal
	threatLevels := assessment.CalculateRiskScores(threatLevelsProfileDir, identifiedThreats)

	if threatLevels == nil {
		fmt.Println("Identifying threat level result is nil.")
	}

	assessment.SaveToFilesystem(threatLevelsOutputFileName, threatLevels)

	// preparedArmTemplate, err := app.PrepareArmExport(armTemplate)
	// if err != nil {
	// 	return err
	// }

	// if err = app.SaveArmTemplateToFileSystem(preparedArmTemplate); err != nil {
	// 	return err
	// }

	return nil
}

var AssessmentCmd = &cobra.Command{
	Use:   "discover",
	Short: "discover takes care of discovering",
	Long:  "discover is a component of Clouditor and takes care of discovering",
	RunE:  doCmd,
}
