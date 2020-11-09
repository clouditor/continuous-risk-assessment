package threatprofile

get_default_names(resource_names) = resource_default_names{    
	resource_default_names := input.template.parameters[i]["defaultValue"]
    resource_names == i
}

storageaccount_nohttps[storageaccount_names] {   
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[i].properties.supportsHttpsTrafficOnly == false

    storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}
