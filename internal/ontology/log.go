package ontology

type Log struct {
	*Auditing
	Activated bool `json:"activated"`
}
