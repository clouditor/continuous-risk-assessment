package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"

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

	fmt.Printf("Auth: %v\n", a.auth)

	return err
}

// ExportArmTemplate exports Azure ARM template from Azure.
func (a App) ExportArmTemplate() (result resources.GroupExportResult, err error) {
	client := resources.NewGroupsClient(viper.GetString(SubscriptionIDFlag))
	client.Authorizer = a.auth

	expReq := resources.ExportTemplateRequest{
		ResourcesProperty: &[]string{"*"},
	}

	result, err = client.ExportTemplate(context.Background(), viper.GetString(ResourceGroupFlag), expReq)

	if err != nil {
		fmt.Println("Error exporting ARM template: ", err)
		return result, err
	}

	return result, err
}

// PrepareArmExport prepares Azure ARM template for saving at file system.
func (a App) PrepareArmExport(armTemplate resources.GroupExportResult) (prepatedArmTemplate []byte, err error) {

	prefix, indent := "", "    "
	prepatedArmTemplate, err = json.MarshalIndent(armTemplate, prefix, indent)
	if err != nil {
		fmt.Println("MarshalIndent failed: ", err)
		return nil, err
	}

	return prepatedArmTemplate, nil
}

// SaveArmTemplateToFileSystem saves Azure ARM template at file system.
func (a App) SaveArmTemplateToFileSystem(armTemplate []byte) (err error) {
	fileTemplate := "/resources/inputs/%s-template.json"
	fileName := fmt.Sprintf(fileTemplate, viper.GetString(ResourceGroupFlag))

	err = ioutil.WriteFile(fileName, armTemplate, 0666)

	if err != nil {
		fmt.Println("Error writing file: ", err)
	}

	fmt.Println("AWS ARM template stored to file system.")

	return nil
}
