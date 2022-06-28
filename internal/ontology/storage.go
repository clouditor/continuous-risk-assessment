package ontology

type Storage struct {
	*CloudResource
	AtRestEncryption *AtRestEncryption `json:"atRestEncryption"`
}
