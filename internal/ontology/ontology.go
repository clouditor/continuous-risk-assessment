package ontology

import (
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
)

type IsCloudResource interface {
	GetID() ResourceID
	GetName() string
	GetType() []string
	HasType(string) bool
	GetCreationTime() *time.Time
}

type ResourceID string

// CloudResource file from Ontology currently not used. How do we merge this file with the 'CloudResource Ontology file'
type CloudResource struct {
	ID           ResourceID `json:"id"`
	Name         string     `json:"name"`
	CreationTime int64      `json:"creationTime"` // is set to 0 if no creation time is available
	// The resource type. It is an array, because a type can be derived from another
	Type []string `json:"type"`
}

func (r *CloudResource) GetID() ResourceID {
	return r.ID
}

func (r *CloudResource) GetName() string {
	return r.Name
}

func (r *CloudResource) GetType() []string {
	return r.Type
}

// HasType checks whether the resource has the particular resourceType
func (r *CloudResource) HasType(resourceType string) (ok bool) {
	for _, value := range r.Type {
		if value == resourceType {
			ok = true
			break
		}
	}

	return
}

func (r *CloudResource) GetCreationTime() *time.Time {
	t := time.Unix(r.CreationTime, 0)
	return &t
}

func ToStruct(r IsCloudResource) (s *structpb.Value, err error) {
	var b []byte

	s = new(structpb.Value)

	// this is probably not the fastest approach, but this
	// way, no extra libraries are needed and no extra struct tags
	// except `json` are required. there is also no significant
	// speed increase in marshaling the whole resource list, because
	// we first need to build it out of the map anyway
	if b, err = json.Marshal(r); err != nil {
		return nil, fmt.Errorf("JSON marshal failed: %v", err)
	}
	if err = json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("JSON unmarshal failed: %v", err)
	}

	return
}

// Storage
type IsStorage interface {
	IsCloudResource

	HasAtRestEncryption
}

type HasAtRestEncryption interface {
	GetAtRestEncryption() *AtRestEncryption
}

type HasHttpEndpoint interface {
	GetHttpEndpoint() *HttpEndpoint
}

func (s *Storage) GetAtRestEncryption() *AtRestEncryption {
	return s.AtRestEncryption
}

// Compute
type IsCompute interface {
	IsCloudResource
}

// Network
type IsNetwork interface {
	IsCloudResource
}
