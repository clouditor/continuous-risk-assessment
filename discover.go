package discovery

import (
	"context"
	"fmt"

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

func (a App) GetAzureArmTemplate() (err error) {
	client := resources.NewGroupsClient(viper.GetString(SubscriptionIDFlag))
	client.Authorizer = a.auth

	var result resources.GroupExportResult
	expReq := resources.ExportTemplateRequest{
		ResourcesProperty: &[]string{"*"},
	}

	result, err = client.ExportTemplate(context.Background(), viper.GetString(ResourceGroupFlag), expReq)

	if err != nil {
		fmt.Println("err: ", err)
		return err
	}

	fmt.Print("Result: ", result)

	return nil
}
