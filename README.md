# continuous-risk-assessment
Prototype for continuous risk assessment

- Retrieve ARM templates https://docs.microsoft.com/en-us/rest/api/resources/resourcegroups/exporttemplate
- Integrate OPA/Rego https://www.openpolicyagent.org/docs/latest/integration/

Next steps:
- Define formalization of threat profiles and the "APIs" of the policy engine and other components
- How to reconstruct attack trees from Rego output
- Add DB for impact assessments and risk scores
- Add shared DB repo for shared threat profiles

Nice to have:
- Retrieve AWS CloudFormation templates https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/resource-import-new-stack.html
- Add some kind of dashboard(?)
- Construct graphical attack trees

Misc:
- We need more use case threat profiles, e.g. Function App has access to storage account, VM is publicly available, open port 22, ...
