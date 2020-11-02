package threats

functionapps_with_access_to_storageaccount[app_names] {
	some i, j
	app_names := [ apps |
    	input.resources[j].type == "Microsoft.Web/sites"
    	contains(
        	input.resources[j].properties.siteConfig.connectionStrings[_].connectionString,
            storageaccount_nohttps[_]
    	)
        input.resources[i].type == "Microsoft.Web/sites"
    	apps := input.resources[i].name
    ]
}

storageaccount_nohttps[storageaccount_names] {
	some i
	storageaccount_names := split(input.resources[i].name, "_")[1]
    input.resources[i].type == "Microsoft.Storage/storageAccounts"
	input.resources[i].properties.supportsHttpsTrafficOnly == false
}

vm_names_with_public_ips[vms_with_publicIPs] {
	# get all interfaces with public IPs
	some j
	publicIPinterfaces := [ pInterfaces |
     	 input.resources[j].type == "Microsoft.Network/networkInterfaces";  
         input.resources[j].properties.ipConfigurations[_].properties.publicIPAddress;
         pInterfaces := input.resources[j] ]
         
	# get all the attached interfaces' ids
	vms_network_interfaces := [ interfaces | 
    	input.resources[_].type == "Microsoft.Compute/virtualMachines"; 
    	interfaces := input.resources[_].properties.networkProfile.networkInterfaces[_][_]]
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
        input.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        attachedInterfaces := input.resources[_].properties.networkProfile.networkInterfaces[_][_];
        vms := input.resources[i].name ]
}

vms_and_interfaces[vms_interfaces] {
	some i
	vms_interfaces := [ x |
        input.resources[i].type == "Microsoft.Compute/virtualMachines"; 
        x := {
        	"vm_name": input.resources[i].name, 
            "interface_ids": input.resources[i].properties.networkProfile.networkInterfaces[_].id
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
    	input.resources[i].properties.networkSecurityGroup.id,
        nsgs_with_port22[_]
    )
    input.resources[i].type == "Microsoft.Network/networkInterfaces"
    interfaces22 := strings.replace_n(
	    {"[": "", ")": "", "]": ""},
    	input.resources[i].name,
    )
}

nsgs_with_port22[nsgs22] {
	some i
    input.resources[i].properties.securityRules[_].properties.destinationPortRange == "22"
    input.resources[i].properties.securityRules[_].properties.access == "Allow"
    input.resources[i].properties.securityRules[_].properties.direction == "Inbound"
    input.resources[i].type == "Microsoft.Network/networkSecurityGroups"
    nsgs22 := strings.replace_n(
	    {"[": "", ")": "", "]": ""},
    	input.resources[i].name,
    )
}