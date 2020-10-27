# continuous-risk-assessment
Prototype for continuous risk assessment

Next steps:
- Retrieve ARM templates https://docs.microsoft.com/en-us/rest/api/resources/resourcegroups/exporttemplate
- Retrieve AWS CloudFormation templates https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html
- Integrate OPA/Rego https://www.openpolicyagent.org/docs/latest/integration/
- Define formalization of threat profiles and the "APIs" of the policy engine and other components
- Add DB for threat profiles, impact evaluations and risk scores
- Add shared DB repo for shared threat profiles
- Add some kind of dashboard(?)

Misc:
- We need more use case threat profiles, e.g. Function App has access to storage account, VM is publicly available, open port 22, ...
