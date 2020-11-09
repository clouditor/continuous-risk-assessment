package threatprofile

get_default_names(resource_names) = resource_default_names{    
	resource_default_names := input.template.parameters[i]["defaultValue"]
    resource_names == i
}

functionapps_with_access_to_storageaccount[app_names] {
    app_names := [ apps |
        input.template.resources[j].type == "Microsoft.Web/sites"
        contains(
            input.template.resources[j].properties.siteConfig.connectionStrings[_].connectionString,
            storageaccount_nohttps[_])
            
            apps := get_default_names(split(input.template.resources[j].name, "'")[1]) 
        ]
}

storageaccount_nohttps[storageaccount_names] {   
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[i].properties.supportsHttpsTrafficOnly == false

    storageaccount_names := get_default_names(split(input.template.resources[i].name, "'")[1])
}

vm_names_with_public_ips[vms_with_publicIPs] {
    # get all interfaces with public IPs
    publicIPinterfaces := [ pInterfaces |
         input.template.resources[j].type == "Microsoft.Network/networkInterfaces";  
         input.template.resources[j].properties.ipConfigurations[_].properties.publicIPAddress;
         pInterfaces := input.template.resources[j] ]
         
    # get all the attached interfaces' ids
    vms_network_interfaces := [ interfaces | 
        input.template.resources[_].type == "Microsoft.Compute/virtualMachines"; 
        interfaces := input.template.resources[_].properties.networkProfile.networkInterfaces[_][_]]
    # the id is inside a string :(
    vm_interfaceIds := 
        trim_right(
            split(vms_network_interfaces[_], ", ")[1],
            ")]",
        )
    # get the intersection        
    vms_with_publicIPs := [ vms |
        contains(publicIPinterfaces[_].name, vm_interfaceIds);
        input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        attachedInterfaces := input.template.resources[_].properties.networkProfile.networkInterfaces[_][_];
        vms := get_default_names(split(input.template.resources[i].name, "'")[1])]
}

vms_and_interfaces[vms_interfaces] {
    vms_interfaces := [ x |
        input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        x := {
            "vm_name": get_default_names(split(input.template.resources[i].name, "'")[1]), 
            # fuer network interfaces auch den default_name aendern?
            "interface_ids": input.template.resources[i].properties.networkProfile.networkInterfaces[_].id
        }
    ]
}

vms_with_open_port22[vms_port22] {
    contains(
        vms_and_interfaces[_][_].interface_ids,
        replace(interfaces_with_open_port22[_], "-", "_")  
    )
    vms_port22 := vms_and_interfaces[_][_].vm_name    
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
