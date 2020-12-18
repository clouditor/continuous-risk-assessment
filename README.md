# continuous-risk-assessment
Prototype for continuous risk assessment

##Usage
Discovery and assessment `go run cmd/main.go`
Assessment with IaC template from filesystem `go run cmd/main.go -p <filepath>`

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
