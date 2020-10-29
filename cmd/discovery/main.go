package main

import (
	"errors"
	"os"
	"strings"

	"clouditor.io/riskAssessment/internal/discovery"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var discoverCmd = &cobra.Command{
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

	discoverCmd.Flags().String(discovery.SubscriptionIDFlag, "", "Subscription ID")
	discoverCmd.Flags().String(discovery.ResourceGroupFlag, "", "Resource Group")
	discoverCmd.Flags().String(discovery.AppTenantIDFlag, "", "Tenant ID of the Azure App")
	discoverCmd.Flags().String(discovery.AppClientIDFlag, "", "Client ID of the Azure App")
	discoverCmd.Flags().String(discovery.AppClientSecretFlag, "", "Client secret of the Azure App")

	viper.BindPFlag(discovery.SubscriptionIDFlag, discoverCmd.Flags().Lookup(discovery.SubscriptionIDFlag))
	viper.BindPFlag(discovery.ResourceGroupFlag, discoverCmd.Flags().Lookup(discovery.ResourceGroupFlag))
	viper.BindPFlag(discovery.AppTenantIDFlag, discoverCmd.Flags().Lookup(discovery.AppTenantIDFlag))
	viper.BindPFlag(discovery.AppClientIDFlag, discoverCmd.Flags().Lookup(discovery.AppClientIDFlag))
	viper.BindPFlag(discovery.AppClientSecretFlag, discoverCmd.Flags().Lookup(discovery.AppClientSecretFlag))
}

func initConfig() {
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.SetEnvPrefix(EnvPrefix)
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

	app := &discovery.App{}
	if err = app.AuthorizeAzure(); err != nil {
		return err
	}

	if err = app.GetAzureArmTemplate(); err != nil {
		return err
	}

	return nil
}

func main() {

	log.SetLevel(log.DebugLevel)

	if err := discoverCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
