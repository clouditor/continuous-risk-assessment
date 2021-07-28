package discovery

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
	// auth autorest.Authorizer
}

// // AuthorizeAzure takes care of the azure authorization.
// func (a *App) AuthorizeAzure() (err error) {
// 	tenantID := viper.GetString(AppTenantIDFlag)
// 	clientID := viper.GetString(AppClientIDFlag)
// 	clientSecret := viper.GetString(AppClientSecretFlag)

// 	if tenantID == "" || clientID == "" || clientSecret == "" {
// 		// fall back to env authorizer
// 		a.auth, err = auth.NewAuthorizerFromEnvironment()
// 	} else {
// 		a.auth, err = auth.NewClientCredentialsConfig(clientID, clientSecret, tenantID).Authorizer()
// 	}

// 	return err
// }

// // DiscoverIacTemplate exports the Azure ARM template from Azure.
// func (a App) DiscoverIacTemplate() (result resources.GroupExportResult, err error) {
// 	log.Info("Export IaC template...")
// 	client := resources.NewGroupsClient(viper.GetString(SubscriptionIDFlag))
// 	client.Authorizer = a.auth

// 	exportTemplateOption := "IncludeParameterDefaultValue"

// 	expReq := resources.ExportTemplateRequest{
// 		ResourcesProperty: &[]string{"*"},
// 		Options:           &exportTemplateOption,
// 	}

// 	result, err = client.ExportTemplate(context.Background(), viper.GetString(ResourceGroupFlag), expReq)

// 	if err != nil {
// 		log.Error("Error exporting IaC template: ", err)
// 		return result, err
// 	}

// 	return result, err
// }
