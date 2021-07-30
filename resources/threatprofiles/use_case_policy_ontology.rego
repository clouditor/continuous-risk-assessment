package threatprofile

# First two polcies mapped to cloudOntologyTemplate of Clouditor

storageaccount_confidentiality_eavesdropOnConnection[storageaccount_names] {   
    input.result[i].type[0] == "ObjectStorage"
    input.result[i].httpEndpoint.transportEncryption.enforced == false

    storageaccount_names := input.result[i].name
}

storageaccount_nohttps[storageaccount_names] {   
    input.result[i].type[0] == "ObjectStorage"
    input.result[i].httpEndpoint.transportEncryption.enabled == false

    storageaccount_names := input.result[i].name
}

# Not yet implemented in ontology discovery
#storageaccount_confidentiality_accessViaPublicLink[storageaccount_names] {
#    input.result[i].type[0] == "ObjectStorage"
#    input.template.resources[i].properties.allowBlobPublicAccess == true
#}

#virtualmachine_availability_performDoSViaSSH[vms] {
#    contains(
#        vms_and_interfaces[_].interface_ids,
#        interfaces_with_open_port22[_]
#    )
#    vms := get_default_names(split(vms_and_interfaces[_].vm_name, "'")[1]) 
#}
#
#
## VMs with disabled DDoS protection
#virtualmachine_availability_performDdoSViaDisbaledProtection[vms] {
#    contains(
#    	vms_and_interfaces[_].interface_ids,
#        networkinterfaces_with_disabled_DDoS_protection[_]
#    )
#    
#   vms := get_default_names(split(vms_and_interfaces[_].vm_name, "'")[1])
#}
#
#
#virtualmachine_integrity_accessViaCompromisedSSHKey[vms] {
#    contains(
#        vms_and_interfaces[_].interface_ids,
#        interfaces_with_open_port22[_]
#    )
#    vms := get_default_names(split(vms_and_interfaces[_].vm_name, "'")[1]) 
#}
#
## helper policy
## Get networkinterface with disabled DDoS protection in corresponding virtual network
#networkinterfaces_with_disabled_DDoS_protection[network_interfaces] {
#	input.template.resources[i].type == "Microsoft.Network/networkInterfaces"
# 	contains(
#    	input.template.resources[i].dependsOn[_], 
#        virtualnetworks[_]
#        )
#
#    network_interfaces := trim(input.template.resources[i].name, "[*]")
#}
#
#
## helper policy
## Get virtualnetwork with disabled DDoS protection
#virtualnetworks[virtualnetwork_name] {
#	input.template.resources[i].type == "Microsoft.Network/virtualNetworks"
#    input.template.resources[i].properties.enableDdosProtection == false
#    
#    virtualnetwork_name := trim(input.template.resources[i].name, "[*]")
#}
#
## helper policy
#interfaces_with_open_port22[interfaces22] {
#    contains(
#        input.template.resources[i].properties.networkSecurityGroup.id,
#        nsgs_with_port22[_]
#    )
#    input.template.resources[i].type == "Microsoft.Network/networkInterfaces"
#    interfaces22 := trim(input.template.resources[i].name, "[*]")
#}
#
## helper policy
#nsgs_with_port22[nsgs22] {
#    input.template.resources[i].properties.securityRules[_].properties.destinationPortRange == "22"
#    input.template.resources[i].properties.securityRules[_].properties.access == "Allow"
#    input.template.resources[i].properties.securityRules[_].properties.direction == "Inbound"
#    input.template.resources[i].type == "Microsoft.Network/networkSecurityGroups"
#    
#    nsgs22 := trim(input.template.resources[i].name, "[*]")
#}
#
## helper function
#get_default_names(resource_names) = resource_default_names{    
#    resource_default_names := input.template.parameters[i]["defaultValue"]
#    resource_names == i
#}
#
## helper policy
#functionapps_with_access_to_storageaccount[app_names] {
#    input.template.resources[j].type == "Microsoft.Web/sites"
#    contains(
#        input.template.resources[j].properties.siteConfig.connectionStrings[_].connectionString,
#        storageaccount_confidentiality_eavesdropOnConnection[_])
#    app_names := trim(input.template.resources[j].name, "[*]")
#}
#
## helper policy
#vms_and_interfaces[vms_interfaces] {
#    input.template.resources[i].type == "Microsoft.Compute/virtualMachines"; 
#    vms_interfaces := {
#        "vm_name": input.template.resources[i].name, 
#        "interface_ids": input.template.resources[i].properties.networkProfile.networkInterfaces[_].id,
#    }
#}
