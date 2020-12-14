package discovery

import (
	"context"
	"encoding/json"
	"io/ioutil"

	log "github.com/sirupsen/logrus"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	"github.com/spf13/viper"
)

// const exported for other Azure specific functions
const (
	SubscriptionIDFlag = "subscriptionID"
	ResourceGroupFlag  = "resourceGroup"

	AppTenantIDFlag     = "app.tenantID"
	AppClientIDFlag     = "app.clientID"
	AppClientSecretFlag = "app.clientSecret"
)

// App Creating a new type "App" containing authorize information.
type App struct {
	auth autorest.Authorizer
}

// AuthorizeAzure takes care of the azure authorization.
func (a *App) AuthorizeAzure() (err error) {
	tenantID := viper.GetString(AppTenantIDFlag)
	clientID := viper.GetString(AppClientIDFlag)
	clientSecret := viper.GetString(AppClientSecretFlag)

	if tenantID == "" || clientID == "" || clientSecret == "" {
		// fall back to env authorizer
		a.auth, err = auth.NewAuthorizerFromEnvironment()
	} else {
		a.auth, err = auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID).Authorizer()
	}

	return err
}

// ExportArmTemplate exports Azure ARM template from Azure.
func (a App) ExportArmTemplate() (result resources.GroupExportResult, err error) {
	log.Info("Export ARM template...")
	client := resources.NewGroupsClient(viper.GetString(SubscriptionIDFlag))
	client.Authorizer = a.auth

	exportTemplateOption := "IncludeParameterDefaultValue"

	expReq := resources.ExportTemplateRequest{
		ResourcesProperty: &[]string{"*"},
		Options:           &exportTemplateOption,
	}

	result, err = client.ExportTemplate(context.Background(), viper.GetString(ResourceGroupFlag), expReq)

	if err != nil {
		log.Error("Error exporting ARM template: ", err)
		return result, err
	}

	return result, err
}

// PrepareArmExport prepares Azure ARM template for saving at file system.
func (a App) PrepareArmExport(armTemplate resources.GroupExportResult) (prepatedArmTemplate []byte, err error) {

	prefix, indent := "", "    "
	prepatedArmTemplate, err = json.MarshalIndent(armTemplate, prefix, indent)
	if err != nil {
		log.Error("MarshalIndent failed: ", err)
		return nil, err
	}

	return prepatedArmTemplate, nil
}

// SaveArmTemplateToFileSystem saves Azure ARM template at file system.
func (a App) SaveArmTemplateToFileSystem(armTemplate []byte, fileName string) (err error) {
	// TODO
	// fileTemplate := "./resources/inputs/%s-template.json"
	// fileName := fmt.Sprintf(fileTemplate, viper.GetString(ResourceGroupFlag))

	err = ioutil.WriteFile(fileName, armTemplate, 0666)

	if err != nil {
		log.Fatal("Error writing file: ", err)
	}

	log.Info("AWS ARM template stored to file system: ", fileName)

	return nil
}
