package discovery

import (
	"context"
	"fmt"
	"strings"

	"clouditor.io/riskAssessment/internal/ontology"

	"github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2019-05-01/resources"

	// "github.com/Azure/azure-sdk-for-go/services/resources/mgmt/2018-02-01/resources"
	// "github.com/Azure/azure-sdk-for-go/profiles/latest/resources/mgmt/resources"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure/auth"
	log "github.com/sirupsen/logrus"
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

// DiscoverIacTemplate exports the Azure ARM template from Azure.
func (a App) DiscoverIacTemplate() (result resources.GroupExportResult, err error) {
	log.Info("Export IaC template...")
	client := resources.NewGroupsClient(viper.GetString(SubscriptionIDFlag))
	client.Authorizer = a.auth

	exportTemplateOption := "IncludeParameterDefaultValue"

	expReq := resources.ExportTemplateRequest{
		ResourcesProperty: &[]string{"*"},
		Options:           &exportTemplateOption,
	}

	result, err = client.ExportTemplate(context.Background(), viper.GetString(ResourceGroupFlag), expReq)

	if err != nil {
		log.Error("Error exporting IaC template: ", err)
		return result, err
	}

	return result, err
}

func (a App) CreateOntologyTemplate(iacTemplate interface{}) ([]ontology.IsCloudResource, error) {

	var list []ontology.IsCloudResource

	for templateKey, templateValue := range iacTemplate.(map[string]interface{}) {

		if templateKey == "resources" {
			resources, ok := templateValue.([]interface{})
			if !ok {
				return nil, fmt.Errorf("templateValue  type convertion failed")
			}

			for _, resourcesValue := range resources {
				value, ok := resourcesValue.(map[string]interface{})
				if !ok {
					return nil, fmt.Errorf("resources type convertion failed")
				}

				for valueKey, valueValue := range value {
					if valueKey == "type" {

						if valueValue.(string) == "Microsoft.Compute/virtualMachines" {
							vm, err := a.createVMResource(value) //, *resourceGroups[i].Name)
							if err != nil {
								return nil, fmt.Errorf("could not create virtual machine resource: %w", err)
							}
							list = append(list, vm)
						}
						// } else if valueValue.(string) == "Microsoft.Network/loadBalancers" {
						// 	lb, err := a.createLBResource(value, *resourceGroups[i].Name)
						// 	if err != nil {
						// 		return nil, fmt.Errorf("could not create load balancer resource: %w", err)
						// 	}
						// 	list = append(list, lb)
						// } else if valueValue.(string) == "Microsoft.Storage/storageAccounts" {
						// 	storage, err := a.createStorageResource(value, *resourceGroups[i].Name)
						// 	if err != nil {
						// 		return nil, fmt.Errorf("could not create storage resource: %w", err)
						// 	}
						// 	list = append(list, storage)
						// }
					}
				}
			}
		}
	}

	return list, nil
}

func (a App) createVMResource(resourceValue map[string]interface{}) (ontology.IsCompute, error) {
	var id string
	var name string
	var enabled bool
	var resourceGroup string

	for key, value := range resourceValue {

		// Get VM name
		if key == "name" {
			name = getDefaultNameOfResource(value.(string))
		}

		// Get bool for Logging enabled
		if key == "properties" {
			properties, ok := value.(map[string]interface{})

			if !ok {
				return nil, fmt.Errorf("type convertion failed")
			}

			for propertiesKey, propertiesValue := range properties {
				if propertiesKey == "diagnosticsProfile" {
					enabled = propertiesValue.(map[string]interface{})["bootDiagnostics"].(map[string]interface{})["enabled"].(bool)
				}
			}
		}
	}

	// Get ID
	// ID must be put together by hand, is not available in template. Better ideas? Leave empty?
	id = a.createID(resourceGroup, resourceValue["type"].(string), name)

	vm := &ontology.VirtualMachine{
		Compute: &ontology.Compute{
			CloudResource: &ontology.CloudResource{
				ID:           ontology.ResourceID(id),
				Name:         name,
				CreationTime: 0, // No creation time available
				Type:         []string{"VirtualMachine", "Compute", "Resource"},
			}},
		Log: &ontology.Log{
			Activated: enabled,
		},
	}

	return vm, nil

}

func (a App) createID(resourceGroup, resourceType, name string) string {
	return "/subscriptions/" + viper.GetString(SubscriptionIDFlag) + "/resourceGroups/" + strings.ToUpper(resourceGroup) + "/providers/" + resourceType + "/" + name
}

func getDefaultNameOfResource(name string) string {
	// Name in template is an parameter and unnecessary information must be shortened
	nameSplit := strings.Split(name, "'")
	anotherNameSplit := strings.Split(nameSplit[1], "_")
	anotherNameSplit = anotherNameSplit[1:]
	anotherNameSplit = anotherNameSplit[:len(anotherNameSplit)-1]
	resourceDefaultName := strings.Join(anotherNameSplit, "-")

	return resourceDefaultName
}
