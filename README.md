# continuous-risk-assessment
Prototype for continuous risk assessment

## Introduction
This repository contains the prototype implementation for the paper _A Continuous Risk Assessment Methodology for Cloud Infrastructures_. The paper can be found [here](https://arxiv.org/pdf/2206.07323.pdf).

The tool consists of 3 parts:
1. Discover cloud system
2. Assess threats
3. Calculate risk scores per asset/protection goal

### Discover cloud system

For the first part, two inputs are needed:
- **description of the cloud envrionment** which must be either an IaC template or an ontology-based template. Currently, it is only possible to automaticly export the Azure IaC template or to autogenerate the ontology-based template by discovering and using the Azure IaC template. If files already exist, they must be located in *resources/inputs/*. The advantages of the ontology-based template can be found in [1].
- **threat profiles** must be created by hand. For identifying threats the policy engine OPA is used and the threat profiles must be written in the policy language Rego. The threat profiles must be located in *resources/threatprofiles/*.

### Assess threats
This part needs as an input
- the identified threats (result of the first step: identify threats) and
- a further Rego policy that maps all assets to their identified attack paths.

The Rego policy for reconstructing the attack paths must be located in *resources/reconstruction/*.

### Calculate risk scores
To calculate the risk scores, two inputs are needed:
- the identified threats (result of the first part 'identitfy threats') and
- the threat and impact values (threatlevels) defined again as Rego policy and located in *resources/threatlevels/*.

In summary, the following files must be specified:
- cloud environment description as IaC template or ontology-based template (optional, otherwise the tool exports the Azure IaC template) (*resources/inputs/*)
- threat profiles as Rego policy (*resources/threatprofiles/*)
- reconstuction profile as Rego policy (*resources/reconstruction/*)
- threatlevels profile as Rego policy (*resources/threatlevels/*)


## Usage
Currently, the risk assessment is executed with both the IaC template and ontology. The IaC template can be either discovered from Azure or passed as input file. The ontology-based template can be transformed from the IaC template or passed as input file.   

Currently, most of the needed paths cannot be passed as parameter. Paths that can be specified as parameters are
- the Azure IaC template (ARM template) path and
- the ontology-based template path.

The other paths for the 
- threat profiles,
- attack tree reconstruction profiles and
- output directories

are given in the code (cmd/assessment/riskAssesment.go).

The Azure credentials must either be passed as command line arguments or via `config.yaml` as follows: 
``` 
subscriptionId: 00000000-0000-0000-0000-000000000000
resourceGroup: resourceGroupName
app:
  tenantId: 00000000-0000-0000-0000-000000000000
  clientId: 00000000-0000-0000-0000-000000000000
  clientSecret: 0000000000000000000000000000000000000 
```

To start the tool without any paths use `go run cmd/main.go`.

To start the risk assessment with an existing IaC template file use `go run cmd/main.go -t <filepath>`.

To start the risk assessment with an existing ontology-based template file use `go run cmd/main.go -o <filepath>`.

To show all possible flags use `go run cmd/main.go -h`.

## Links
Preprint of the paper: https://arxiv.org/pdf/2206.07323.pdf
