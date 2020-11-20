package discovery

import (
	"errors"
	"os"
	"strings"

	"clouditor.io/riskAssessment/internal/discovery"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var DiscoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "discover takes care of discovering",
	Long:  "discover is a component of Clouditor and takes care of discovering",
	RunE:  doCmd,
}

const (
	EnvPrefix = "CLOUDITOR"
)

func init() {
	cobra.OnInitialize(initConfig)

	DiscoverCmd.Flags().String(discovery.SubscriptionIDFlag, "", "Subscription ID")
	DiscoverCmd.Flags().String(discovery.ResourceGroupFlag, "", "Resource Group")
	DiscoverCmd.Flags().String(discovery.AppTenantIDFlag, "", "Tenant ID of the Azure App")
	DiscoverCmd.Flags().String(discovery.AppClientIDFlag, "", "Client ID of the Azure App")
	DiscoverCmd.Flags().String(discovery.AppClientSecretFlag, "", "Client secret of the Azure App")

	viper.BindPFlag(discovery.SubscriptionIDFlag, DiscoverCmd.Flags().Lookup(discovery.SubscriptionIDFlag))
	viper.BindPFlag(discovery.ResourceGroupFlag, DiscoverCmd.Flags().Lookup(discovery.ResourceGroupFlag))
	viper.BindPFlag(discovery.AppTenantIDFlag, DiscoverCmd.Flags().Lookup(discovery.AppTenantIDFlag))
	viper.BindPFlag(discovery.AppClientIDFlag, DiscoverCmd.Flags().Lookup(discovery.AppClientIDFlag))
	viper.BindPFlag(discovery.AppClientSecretFlag, DiscoverCmd.Flags().Lookup(discovery.AppClientSecretFlag))
}

func initConfig() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix(EnvPrefix)
	viper.AutomaticEnv()
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath("../../")

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

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	armTemplate, err = app.ExportArmTemplate()
	if err != nil {
		return err
	}

	// preparedArmTemplate, err := app.PrepareArmExport(armTemplate)
	// if err != nil {
	// 	return err
	// }

	// if err = app.SaveArmTemplateToFileSystem(preparedArmTemplate); err != nil {
	// 	return err
	// }

	return nil
}

func main() {

	log.SetLevel(log.DebugLevel)

	if err := DiscoverCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
