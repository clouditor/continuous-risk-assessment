# continuous-risk-assessment
Prototype for continuous risk assessment

Threat Profiles:
- "Microsoft.Network/networkSecurityGroups"
  - Number of open ports? -> Kann das helfen?

- "Microsoft.Network/networkSecurityGroups/securityRules"
  - set "sourceAddressPrefixes" 

- "Microsoft.Network/virtualNetworks"
  - "enableDdosProtection"
  - "enableVmProtection"
  - is it possible that the location of the VM and the network interface/security group are different?

- ~~"Microsoft.Storage/storageAccounts"~~
  - ~~encryption (Oder sind die eh immer verschlüsselt?)~~
  - ~~"networkAcls"/"ipRules" ~~

- "Microsoft.Storage/storageAccounts/blobServices/containers"
  - "publicAccess"

Tasks:
- ~~Retrieve ARM templates https://docs.microsoft.com/en-us/rest/api/resources/resourcegroups/exporttemplate~~
- ~~Integrate OPA/Rego https://www.openpolicyagent.org/docs/latest/integration/~~
- ~~Reconstruct attack trees from Rego output: https://play.openpolicyagent.org/p/eZF4hFltsX~~
- ~~Identify the maximum threat level for one attack tree: https://play.openpolicyagent.org/p/InDrHI6jJy~~
- ~~Impact and threat values are specified in the Data document~~

Next steps:
- Define formalization of threat profiles and the "APIs" of the policy engine and other components
  - possible naming schema: assettype_protectiongoal_leafnodedescription, e.g. storageaccount_confidentiality_eavesdrop
  - possible impact naming schema: assetID_protectiongoal_value
- Handle the case of non-available threat profiles/values and non-available impact-values in Rego 
- Prepare repo for publication
  - Mention in the paper that it is "part of the Clouditor" 

Nice to have:
- Retrieve AWS CloudFormation templates https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html
- Add some kind of dashboard: we could write a logstash pipe to format the asset names and risk scores to display nicely in Kibana
- Construct graphical attack trees: there are open-source tools for that (https://github.com/JimmyThompson/ent) but this is probably something for future work
- Create cloud resource ontology

Misc:
- We need more use case threat profiles, e.g. Function App has access to storage account, VM is publicly available, open port 22, ...
  - Kubernetes paths (e.g. Storage Account can be mounted)
  - IoT Hub writes to storage account
  - Theoretically, we could also model our AWS data flow tracking experiments: identify objects that have the REPLICA flag set but their content hash is nowhere else to be found
  - KMS key availability concerns storage account availability
