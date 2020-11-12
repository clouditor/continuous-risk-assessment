package threatprofile


storageaccount_integrity_uploadFromMaliciousIoTDevice[storageaccount_names] {   
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[j].type == "Microsoft.Devices/IotHubs"
    contains(
        input.template.resources[j].properties.routing.endpoints.storageContainers[_].connectionString,
        input.template.parameters[split(input.template.resources[i].name, "'")[1]]["defaultValue"]
    )

    storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}

storageaccount_confidentiality_eavesdropOnConnection[storageaccount_names] {   
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[i].properties.supportsHttpsTrafficOnly == false

    storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}

storageaccount_confidentiality_accessPublicly[storageaccount_names] {
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[i].properties.allowBlobPublicAccess == true

    storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}

virtualmachine_availability_performDoSViaSSH[vms_port22] {
    contains(
        vms_and_interfaces[_].interface_ids,
        replace(interfaces_with_open_port22[_], "-", "_")  
    )
    vms_port22 := vms_and_interfaces[_].vm_name    
}

interfaces_with_open_port22[interfaces22] {
    contains(
        input.template.resources[i].properties.networkSecurityGroup.id,
        replace(nsgs_with_port22[_], "-", "_")
    )
    input.template.resources[i].type == "Microsoft.Network/networkInterfaces"
    interfaces22 := get_default_names(split(input.template.resources[i].name, "'")[1])
}

nsgs_with_port22[nsgs22] {
    input.template.resources[i].properties.securityRules[_].properties.destinationPortRange == "22"
    input.template.resources[i].properties.securityRules[_].properties.access == "Allow"
    input.template.resources[i].properties.securityRules[_].properties.direction == "Inbound"
    input.template.resources[i].type == "Microsoft.Network/networkSecurityGroups"
    
    nsgs22 := get_default_names(split(input.template.resources[i].name, "'")[1]) #input.template.resources[i].name
}


get_default_names(resource_names) = resource_default_names{    
    resource_default_names := input.template.parameters[i]["defaultValue"]
    resource_names == i
}

functionapps_with_access_to_storageaccount[app_names] {
    input.template.resources[j].type == "Microsoft.Web/sites"
    contains(
        input.template.resources[j].properties.siteConfig.connectionStrings[_].connectionString,
        storageaccount_confidentiality_eavesdropOnConnection[_])
    app_names :=   get_default_names(split(input.template.resources[j].name, "'")[1]) 
}

vms_and_interfaces[vms_interfaces] {
    input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
    vms_interfaces := {
        "vm_name": get_default_names(split(input.template.resources[i].name, "'")[1]), 
        # fuer network interfaces auch den default_name aendern?
        "interface_ids": input.template.resources[i].properties.networkProfile.networkInterfaces[_].id
    }
}