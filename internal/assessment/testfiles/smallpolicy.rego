package example.threats

storageaccount_confidentiality_accessPublicly[storageaccount_names] {
	input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
	input.template.resources[i].properties.allowBlobPublicAccess == true

	storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}
get_default_names(resource_names) = resource_default_names{    
	resource_default_names := input.template.parameters[i]["defaultValue"]
	resource_names == i
}