package threats

functionapps_with_access_to_storageaccount[app_names] {
    some i, j
    app_names := [ apps |
        input.template.resources[j].type == "Microsoft.Web/sites"
        contains(
            input.template.resources[j].properties.siteConfig.connectionStrings[_].connectionString,
            storageaccount_nohttps[_]
        )
        input.template.resources[i].type == "Microsoft.Web/sites"
        apps := input.template.resources[i].name
    ]
}

storageaccount_nohttps[storageaccount_names] {
    some i
    storageaccount_names := split(input.template.resources[i].name, "_")[1]
    input.template.resources[i].type == "Microsoft.Storage/storageAccounts"
    input.template.resources[i].properties.supportsHttpsTrafficOnly == false
}

vm_names_with_public_ips[vms_with_publicIPs] {
    # get all interfaces with public IPs
    some j
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
    some i
    vms_with_publicIPs := [ vms |
        contains(publicIPinterfaces[_].name, vm_interfaceIds);
        input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        attachedInterfaces := input.template.resources[_].properties.networkProfile.networkInterfaces[_][_];
        vms := input.template.resources[i].name ]
}

vms_and_interfaces[vms_interfaces] {
    some i
    vms_interfaces := [ x |
        input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        x := {
            "vm_name": input.template.resources[i].name, 
            "interface_ids": input.template.resources[i].properties.networkProfile.networkInterfaces[_].id
        }
    ]
}

vms_with_open_port22[vms_port22] {
    contains(
        vms_and_interfaces[_][_].interface_ids,
        interfaces_with_open_port22[_]   
    )
    vms_port22 := vms_and_interfaces[_][_].vm_name
    
}

interfaces_with_open_port22[interfaces22] {
    contains(
        input.template.resources[i].properties.networkSecurityGroup.id,
        nsgs_with_port22[_]
    )
    input.template.resources[i].type == "Microsoft.Network/networkInterfaces"
    interfaces22 := strings.replace_n(
        {"[": "", ")": "", "]": ""},
        input.template.resources[i].name,
    )
}

nsgs_with_port22[nsgs22] {
    some i
    input.template.resources[i].properties.securityRules[_].properties.destinationPortRange == "22"
    input.template.resources[i].properties.securityRules[_].properties.access == "Allow"
    input.template.resources[i].properties.securityRules[_].properties.direction == "Inbound"
    input.template.resources[i].type == "Microsoft.Network/networkSecurityGroups"
    nsgs22 := strings.replace_n(
        {"[": "", ")": "", "]": ""},
        input.template.resources[i].name,
    )
}