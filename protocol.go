package project

import ()

// Quorum is an interface for interacting with a replica.
type Quorum interface {
	// Read requests a file from a replica.
	Read(req *ReadRequest, resp *ReadResponse) error

	// Write attempts to write a file to a replica.
	// Due to the lock-free quorum consistency protocol used here,
	// Write can be pre-empted if a higher-priority server ID was
	// writing at the same time; this is not an error case, and will
	// be reflected in the response.
	Write(req *WriteRequest, resp *WriteResponse) error

	ClientRead(req *ClientReadRequest, resp *ClientReadResponse) error

	ClientWrite(req *ClientWriteRequest, resp *ClientWriteResponse) error

	ClientCryptoReplicas(req *ClientCryptoReplicasRequest, resp *ClientCryptoReplicasResponse) error
}

// ReadRequest represents a request to read a file from a replica.
type ReadRequest struct {
	Filename        string
	DigestOnly      bool
	LatencyMillis   int
	IsKeyRead       bool
	ClientPublicKey []byte
}

type ReadResponse struct {
	Found       bool
	Version     int
	TID         uint64
	Data        []byte
	FromReplica int
	Secure      bool
	Hash
}

// WriteRequest represents a request to write a file to a replica.
type WriteRequest struct {
	Version       int
	TID           uint64
	Filename      string
	Data          []byte
	LatencyMillis int
	Secure        bool

	// TagWithTID indicates that the filename should
	// be tagged with the transaction ID, which essentially
	// guarantees the novelty, success, and immutability of
	// the write. The set of replicas WILL NOT CHANGE, even
	// though the filename will.
	// TODO: decouple TagWithTID and the notion of "IsKeyWrite",
	// e.g. in the write handler where it demarshals & modifies
	// the key pieces
	TagWithTID bool
}

type WriteResponse struct {
	Success bool
	TID     uint64
}

type ClientReadRequest struct {
	Filename        string
	DigestOnly      bool
	FakeLatency     bool
	ClientPublicKey []byte
}

type ClientReadResponse struct {
	Success            bool
	Found              bool
	EncryptedKeyPieces []string
	KeySuccess         bool
	KeyFound           bool
	Data               []byte
	Secure             bool
	Version            int
	TID                uint64
	Hash
}

type ClientWriteRequest struct {
	Filename    string
	Data        []byte
	Secure      bool
	KeyPieces   map[int]string
	FakeLatency bool
}

type ClientWriteResponse struct {
	Success    bool
	Overridden bool
	TID        uint64
}

type ClientCryptoReplicasRequest struct {
	Filename string
}

type ClientCryptoReplicasResponse struct {
	ReplicaPubKeys map[int]string
}
