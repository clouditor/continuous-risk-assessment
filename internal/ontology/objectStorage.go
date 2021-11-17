package ontology

type ObjectStorage struct {
	*Storage
	HttpEndpoint *HttpEndpoint `json:"httpEndpoint"`
}
