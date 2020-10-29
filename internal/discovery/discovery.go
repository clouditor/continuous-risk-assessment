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

const (
	SubscriptionIDFlag = "subscriptionID"
	ResourceGroupFlag  = "resourceGroup"

	AppTenantIDFlag     = "app.tenantID"
	AppClientIDFlag     = "app.clientID"
	AppClientSecretFlag = "app.clientSecret"
)

type App struct {
	auth autorest.Authorizer
}

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

func (a App) exportArmTemplate() (result resources.GroupExportResult, err error) {
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

func (a App) GetAzureArmTemplate() (err error) {

	armTemplate, err := a.exportArmTemplate()

	if err != nil {
		return err
	}

	prefix, indent := "", "    "
	exported, err := json.MarshalIndent(armTemplate, prefix, indent)
	if err != nil {
		fmt.Println("MarshalIndent failed: ", err)
		return err
	}

	err = saveToFileSystem(exported)

	if err != nil {
		return err
	}

	return nil
}

func saveToFileSystem(fileContent []byte) (err error) {
	fileTemplate := "%s-template.json"
	fileName := fmt.Sprintf(fileTemplate, viper.GetString(ResourceGroupFlag))

	err = ioutil.WriteFile(fileName, fileContent, 0666)

	if err != nil {
		fmt.Println("Error writing file: ", err)
	}

	fmt.Println("AWS ARM template stored to file system.")

	return nil
}