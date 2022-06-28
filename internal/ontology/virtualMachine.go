package ontology

type VirtualMachine struct {
	*Compute
	NetworkInterface []ResourceID `json:"networkInterface"`
	BlockStorage     []ResourceID `json:"blockStorage"`
	Log              *Log         `json:"log"`
}
