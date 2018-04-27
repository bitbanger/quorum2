package project

const (
	RSA_KEY_BITS = 2048

	START_PORT = 1234

	DATA_REPLICAS = 5
	KEY_REPLICAS  = 10

	// This can be set higher (as high as (DATA_REPLICAS - DATA_REPLICAS/2))
	// to increase the number of machines guaranteed to be able to resolve
	// concurrent writes.
	QUORUM_REDUNDANCY = 1
)

var (
	READ_QUORUM  = DATA_REPLICAS/2 + QUORUM_REDUNDANCY
	WRITE_QUORUM = DATA_REPLICAS/2 + QUORUM_REDUNDANCY

	// The key quorum is semantically slightly different
	// from the other quora: it doesn't refer to the quorum
	// required to read the key, because keys are marked with
	// TIDs, unique to replicas, and never overwritten. Instead,
	// it refers to the number of key pieces in different countries
	// necessary to re-assemble the file's symmetric key. Higher is
	// more secure and slower.
	KEY_QUORUM = 3
)
