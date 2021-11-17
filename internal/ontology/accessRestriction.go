package ontology

type AccessRestriction struct {
	*Authorization
	Inbound         bool   `json:"inbound"`
	RestrictedPorts string `json:"restrictedPorts"`
}
