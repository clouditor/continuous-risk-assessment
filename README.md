# continuous-risk-assessment
Prototype for continuous risk assessment

- Retrieve ARM templates https://docs.microsoft.com/en-us/rest/api/resources/resourcegroups/exporttemplate
- Integrate OPA/Rego https://www.openpolicyagent.org/docs/latest/integration/
- Reconstruct attack trees from Rego output: https://play.openpolicyagent.org/p/eZF4hFltsX
- Identify the maximum threat level for one attack tree: https://play.openpolicyagent.org/p/InDrHI6jJy

Next steps:
- Define formalization of threat profiles and the "APIs" of the policy engine and other components
  - possible naming schema: assettype_protectiongoal_leafnodedescription, e.g. storageaccount_confidentiality_eavesdrop
- Add DB for impact assessments and risk scores
  - Impacts could be specified in the Rego Data
- Add shared DB repo for shared threat profiles
  - Should this be a public github repo?

Nice to have:
- Retrieve AWS CloudFormation templates https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html
- Add some kind of dashboard: we could write a logstash pipe to format the asset names and risk scores to display nicely in Kibana
- Construct graphical attack trees: there are open-source tools for that (https://github.com/JimmyThompson/ent) but this is probably something for future work

Misc:
- We need more use case threat profiles, e.g. Function App has access to storage account, VM is publicly available, open port 22, ...
  - Kubernetes paths (e.g. Storage Account can be mounted)
  - IoT Hub writes to storage account
  - Theoretically, we could also model our AWS data flow tracking experiments: identify objects that have the REPLICA flag set but their content hash is nowhere else to be found
  - KMS key availability concerns storage account availability
