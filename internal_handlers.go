package project

import (
	"crypto/rsa"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"
)

// TODO: manual recovery after rebooting
//       read repairs may be good enough for non-keys
// TODO: test failure in general

type Item struct {
	Version int
	TID     uint64
	Secure  bool
	Data    []byte
}

// QuorumServer is an implementation of the Quorum interface.
type QuorumServer struct {
	replicaID      int
	numReplicas    int
	storage        map[string]*Item
	locks          map[string]*sync.RWMutex
	locksLock      *sync.RWMutex
	replicaPubKeys map[int]*rsa.PublicKey
	publicKey      *rsa.PublicKey
	privateKey     *rsa.PrivateKey
}

func newQuorumServer(replicaID, numReplicas int, replicaPubKeys map[int]*rsa.PublicKey, privateKey *rsa.PrivateKey, publicKey *rsa.PublicKey) *QuorumServer {
	return &QuorumServer{
		replicaID:      replicaID,
		numReplicas:    numReplicas,
		storage:        make(map[string]*Item),
		locks:          make(map[string]*sync.RWMutex),
		locksLock:      &sync.RWMutex{},
		replicaPubKeys: replicaPubKeys,
		publicKey:      publicKey,
		privateKey:     privateKey,
	}
}

func (q *QuorumServer) getFileLock(filename string) *sync.RWMutex {
	// Try to get the lock for this file.
	q.locksLock.RLock
	fileLock, ok := q.locks[filename]
	q.locksLock.RUnlock()

	if ok {
		return fileLock
	}

	// We need to add the lock.

	// If someone else performs a write before this write lock, that's fine.
	// It doesn't matter who does it, and it only has to happen once.

	q.locksLock.Lock()
	if _, ok := q.locks[filename]; !ok {
		fileLock = &sync.RWMutex{}
		q.locks[filename] = fileLock
	}
	q.locksLock.Unlock()

	return fileLock
}

func (q *QuorumServer) tryGetFileLock(filename string) (*sync.RWMutex, bool) {
	// Try to get the lock for this file.
	q.locksLock.RLock()
	fileLock, ok := q.locks[filename]
	q.locksLock.RUnlock()

	return fileLock, ok
}

func (q *QuorumServer) Read(req *ReadRequest, resp *ReadResponse) error {
	resp.FromReplica = q.replicaID

	if req.LatencyMillis > 0 {
		time.Sleep(time.Duration(req.LatencyMillis) * time.Millisecond)
	}

	lock, ok := q.tryGetFileLock(req.Filename)
	if !ok {
		resp.Found = false
		return nil
	}

	lock.RLock()

	item, ok := q.storage[req.Filename]
	if !ok {
		lock.RUnlock()
		resp.Found = false
		return nil
	}

	resp.Version = item.Version
	resp.TID = item.TID
	resp.Secure = item.Secure
	resp.Found = true

	resp.Hash = sha256.Sum256(item.Data)

	if !req.DigestOnly {
		if req.IsKeyRead {
			// We should only return our key piece, decrypted with our
			// private key but re-encrypted with the client's public key.

			if req.ClientPublicKey == nil {
				// We can't return our key piece without encrypting it
				// with a valid client public key.
				return fmt.Errorf("can't return a key piece without encrypting it with a client public key")
			}

			clientPublicKey, err := unmarshalPublicKey(req.ClientPublicKey)
			if err != nil {
				return fmt.Errorf("invalid client public key on a key piece read request")
			}

			keyPieces, err := unmarshalKeyPieces(item.Data)
			if err != nil {
				return fmt.Errorf("error unmarshalling key pieces: %s", err)
			}

			ourEncryptedKeyPiece, ok := keyPieces[q.replicaID]
			if !ok {
				return fmt.Errorf("BAD PROBLEM: this replica didn't have its own key piece!")
			}

			ourKeyPiece, err := decryptRSA([]byte(ourEncryptedKeyPiece), q.privateKey)
			if err != nil {
				return fmt.Errorf("error decrypting our key piece: %s", err)
			}

			encKeyPiece, err := encryptRSA(ourKeyPiece, clientPublicKey)
			if err != nil {
				return fmt.Errorf("error encrypting our key piece with the client's public key: %s", err)
			}

			resp.Data = []byte(encKeyPiece)
		} else {
			resp.Data = item.Data
		}
	}

	lock.RUnlock()

	return nil
}

func (q *QuorumServer) Write(req *WriteRequest, resp *WriteResponse) error {
	resp.TID = req.TID

	if req.LatencyMillis > 0 {
		time.Sleep(time.Duration(req.LatencyMillis) * time.Millisecond)
	}

	if version := req.Version; version < 0 {
		return fmt.Errorf("invalid write request: item version cannot be less than 0 (got %d)", version)
	}

	actualFilename := req.Filename
	if req.TagWithTID {
		actualFilename = fmt.Sprintf("%s_%s", actualFilename, tid64(req.TID))

		if _, err := unmarshalKeyPieces(req.Data); err != nil {
			return fmt.Errorf("invalid write request: error unmarshaling key pieces: %s", err)
		}

		// This means it's key pieces (see the TODO on the TagWithID
		// field description in protocol.go), so we need to decrypt
		// our own.

		// TODO: decrypt w/ this replica's private key
		// TODO immediately after that: actually unmarshal and remarshal
		// TODO way after that: decrypt w/ this COUNTRY'S private key
	}

	lock := q.getFileLock(actualFilename)

	lock.Lock()

	item, ok := q.storage[actualFilename]

	if !ok {
		// The item doesn't exist yet. We can create it.
		q.storage[actualFilename] = &Item{
			Version: req.Version,
			TID:     req.TID,
			Secure:  req.Secure,
			Data:    req.Data,
		}

		// fmt.Printf("replica %d wrote %q to key %s (version %d, writer %d)\n", q.replicaID, req.Data, req.Filename, req.Version, req.TID)

		resp.Success = true
		lock.Unlock()
		return nil
	}

	// If the TID-tagged item existed, that's not good. It either means
	// there was a bug, or two stores of the same data item had a TID
	// collision (probably the former). Note that this means successful TID-tagged
	// writes are not idempotent, which may cause the bug if we forget that later
	// on and re-try writes that may have succeeded.
	if req.TagWithTID {
		fmt.Printf("PROBLEM: TID collision for TID-tagged data write! (replica %d, TID %s)\n", q.replicaID, tid64(req.TID))
	}

	if ok && item.Version > req.Version {
		lock.Unlock()
		return nil
	}

	// If the versions collide, break ties with the TID.
	if ok && item.Version == req.Version && req.TID < item.TID {
		lock.Unlock()
		return nil
	}

	// If we're here, that means that our version number is either greater than the
	// current version number, or equal but we have priority. We can go ahead with the write.

	item.Version = req.Version
	item.TID = req.TID
	item.Secure = req.Secure
	item.Data = req.Data

	// fmt.Printf("replica %d wrote %q to key %s (version %d, writer %d)\n", q.replicaID, req.Data, req.Filename, req.Version, req.TID)

	lock.Unlock()

	resp.Success = true
	return nil
}
