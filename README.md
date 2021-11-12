# continuous-risk-assessment
Prototype for continuous risk assessment

## Introduction
continuous-risk-assessment is an prototype for a semi-automated continous risk assessment for cloud environments. The corresponding paper can be found [here][1].

The tool consists of 3 parts:
1. Identify threats
2. Reconstruct attack paths (identify all attack paths per asset)
3. Calculate risk scores per asset/protection goal

### Identitfy threats

For the first part 2 inputs are needed:
- **description of the cloud envrionment** which must be either an IaC template or an ontology-based template. Currently, it is only possible to automaticly export the Azure IaC template or to autogenerate the ontology-based template by discovering and using the Azure IaC template. If files already exist, they must be located in *resources/inputs/*. The advantages of the ontology-based template can be found in [1].
- **threat profiles** must be created by hand. For identifying threats the policy engine OPA is used and the threat profiles must be written in the policy language Rego. The threat profiles must be located in *resources/threatprofiles/*.

### Reconstruct attack paths
This part needs as an input
- the identified threats (result of the first step: identify threats) and
- a further Rego policy that maps all assets to their identified attack paths.

The Rego policy for reconstructing the attack paths must be located in *resources/reconstruction/*.

### Calculate risk scores
To calculate the risk scores 2 inputs are needed:
- the identified threats (result of the first part 'identitfy threats') and
- the threat and impact values (threatlevels) defined again as Rego policy and located in *resources/threatlevels/*.

In summary, the following files must be specified:
- cloud environment description as IaC template or ontology-based template (optional, otherwise the tool exports the Azure IaC template) (*resources/inputs/*)
- threat profiles as Rego policy (*resources/threatprofiles/*)
- reconstuction profile as Rego policy (*resources/reconstruction/*)
- threatlevels profile as Rego policy (*resources/threatlevels/*)


## Usage
**Currently, the risk assessment is performed both with the IaC template (discovered or as file given as parameter) and with the ontology-based template (translated from the IaC template or as file given as parameter).**

Currently, most of the needed paths cannot be passed as parameter. The only paths that can be specified as parameters are
- the Azure IaC template (ARM template) path and
- the ontology-based template path.

The other paths are given in the code (cmd/assessment/riskAssesment.go)

To start the tool without any paths to start the Azure discovery and the risk assessment use `go run cmd/main.go`.

To start the risk assessment with an IaC template file from the filesystem use `go run cmd/main.go -t <filepath>`.

To start the risk assessment with an ontology-based template file from the filesystem use `go run cmd/main.go -o <filepath>`.

To show all prossible flags use `go run cmd/main.go -h`.

## Next steps
- Define formalization of threat profiles and the "APIs" of the policy engine and other components
  - possible naming schema: assettype_protectiongoal_leafnodedescription, e.g. storageaccount_confidentiality_eavesdrop
  - possible impact naming schema: assetID_protectiongoal_value
- Handle the case of non-available threat profiles/values and non-available impact-values in Rego
- Prepare repo for publication
  - Mention in the paper that it is "part of the Clouditor"

## Nice to have
- Retrieve AWS CloudFormation templates https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html
- Add some kind of dashboard: we could write a logstash pipe to format the asset names and risk scores to display nicely in Kibana
- Construct graphical attack trees: there are open-source tools for that (https://github.com/JimmyThompson/ent) but this is probably something for future work

Misc:
- We need more use case threat profiles, e.g. Function App has access to storage account, VM is publicly available, open port 22, ...
  - Kubernetes paths (e.g. Storage Account can be mounted)
  - IoT Hub writes to storage account
  - Theoretically, we could also model our AWS data flow tracking experiments: identify objects that have the REPLICA flag set but their content hash is nowhere else to be found
  - KMS key availability concerns storage account availability


## Links
[1] https://git-int.aisec.fraunhofer.de/sas/pub/2020-continuous-risk-assessment/-/tree/master/STM%20submission
