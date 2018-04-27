package project

import (
	// "crypto/rsa"
	// "crypto/sha256"
	"fmt"
	"math/rand"
	// "strings"
)

func (q *QuorumServer) ClientRead(req *ClientReadRequest, resp *ClientReadResponse) error {
	// The client wants to read a file.

	// Get the file first (before we need to know whether to decrypt it).
	// We don't need to provide a TID for a file read, and the client's
	// public key can be nil since we aren't asking for the keys yet.
	latestRespSlice, success, found := q.doReads(req.Filename, req.DigestOnly, false, 0, req.FakeLatency, nil)
	if !success {
		return nil
	}

	if !found {
		resp.Success = true
		return nil
	}
	switch {
	case !success:
		return nil
	case !found:
		resp.Success = true
		return nil
	}

	// TODO: fix the case interpretation for this for the key cases
	resp.Success = true
	resp.Found = true

	latestResp := latestRespSlice[0]

	resp.Version = latestResp.Version
	resp.TID = latestResp.TID
	resp.Hash = latestResp.Hash
	resp.Secure = latestResp.Secure
	if !req.DigestOnly {
		resp.Data = latestResp.Data
	}

	// We're good here for insecure files.
	if !latestResp.Secure {
		return nil
	}

	// If it's a secure file, the client doesn't just want the digests,
	// and the client didn't provide a valid public key, they're out of
	// luck; we can't pass key pieces in the clear.
	if !req.DigestOnly {
		if req.ClientPublicKey == nil {
			return fmt.Errorf("can't perform a read on a secure file without a public key for the reading client")
		}

		if _, err := unmarshalPublicKey(req.ClientPublicKey); err != nil {
			return fmt.Errorf("invalid client public key on a key piece read request")
		}
	}

	// For secure files, now we need to get the key, unless the client
	// only wants digests. [ In that case, the client is probably
	// internal, improperly calling client functions to make life
	// easier ;) ]
	if !req.DigestOnly {
		keyResps, success, found := q.doReads(req.Filename, false, true, resp.TID, req.FakeLatency, req.ClientPublicKey)
		switch {
		case !success:
			return nil
		case !found:
			resp.KeySuccess = true
			return nil
		}

		resp.KeySuccess = true
		resp.KeyFound = true

		// We only need KEY_QUORUM pieces, so we can save a bit on network bandwidth, here.
		// resp.EncryptedKeyPieces = strings.Split(string(keyResps[0].Data), " ")[:KEY_QUORUM]
		for _, keyResp := range keyResps[:KEY_QUORUM] {
			resp.EncryptedKeyPieces = append(resp.EncryptedKeyPieces, string(keyResp.Data))
		}
	}

	return nil
}

func (q *QuorumServer) doReads(preFilename string, digestOnly bool, keyRead bool, tid uint64, fakeLatency bool, clientPublicKeyBytes []byte) ([]*ReadResponse, bool, bool) {
	filename := preFilename

	var replicas []int
	if keyRead {
		replicas = replicasForKey(filename, KEY_REPLICAS, q.numReplicas)
	} else {
		replicas = replicasForKey(filename, DATA_REPLICAS, q.numReplicas)
	}

	// Tag it with the TID for keys, after calculating the replica set.
	if keyRead {
		filename = fmt.Sprintf("%s_%s", preFilename, tid64(tid))
	}

	responses := make(chan *ReadResponse, len(replicas))

	needSuccesses := READ_QUORUM
	if keyRead {
		needSuccesses = KEY_QUORUM
	}

	// Ask all of the replicas for the file.
	selfReplica := false
	for _, replica := range replicas {
		// fmt.Printf("asking replica %d\n", replica)
		if replica == q.replicaID {
			// If we're one of the replicas, we'll handle that separately.
			selfReplica = true
			continue
		}

		// Make the read requests in the background and put the
		// results on a channel so we can count for a quorum.
		go func(replica int) {
			latencyMillis := 0
			if fakeLatency {
				latencyMillis = rand.Intn(5000)
			}

			replicaResp, err := readReq(&ReadRequest{
				Filename:        filename,
				DigestOnly:      digestOnly,
				LatencyMillis:   latencyMillis,
				IsKeyRead:       keyRead,
				ClientPublicKey: clientPublicKeyBytes,
			}, replica)

			if err != nil {
				fmt.Printf("read RPC error: %s\n", err)
				responses <- nil
				return
			}

			// fmt.Printf("read response: %+v\n", replicaResp)
			responses <- replicaResp
		}(replica)
	}

	// Handle the case where we're a replica.
	// We'll just make a fake response to minimize extra code.
	if selfReplica {
		/*selfResp := &ReadResponse{}
		lock, ok := q.tryGetFileLock(filename)
		if !ok {
			selfResp.Found = false
		} else {
			lock.RLock()
			item, ok := q.storage[filename]
			if !ok {
				selfResp.Found = false
			} else {
				selfResp.Found = true
				selfResp.Version = item.Version
				selfResp.TID = item.TID
				if !digestOnly {
					selfResp.Data = item.Data
				}
				selfResp.Hash = sha256.Sum256(item.Data)
			}
			lock.RUnlock()
		}

		responses <- selfResp*/
		latencyMillis := 0
		if fakeLatency {
			latencyMillis = rand.Intn(5000)
		}

		selfReadReq := &ReadRequest{
			Filename:        filename,
			DigestOnly:      digestOnly,
			LatencyMillis:   latencyMillis,
			IsKeyRead:       keyRead,
			ClientPublicKey: clientPublicKeyBytes,
		}

		var selfReadResp ReadResponse

		if err := q.Read(selfReadReq, &selfReadResp); err != nil {
			responses <- nil
		} else {
			responses <- &selfReadResp
		}
	}

	failures := 0
	notFounds := 0
	successResps := []*ReadResponse{}
	// POSSIBLE TODO: fix this (and the one in ClientWrite) to time out independently of
	// the RPCs, and don't block expecting q.numReplicas responses?
	// for replicaResp := range responses {
	for i := 0; i < q.numReplicas; i++ {
		replicaResp := <-responses

		switch {
		case replicaResp == nil:
			failures++
		case !replicaResp.Found:
			notFounds++
		default:
			successResps = append(successResps, replicaResp)
		}

		if len(successResps) >= needSuccesses || (failures+notFounds) > (len(replicas)-needSuccesses) {
			break
		}
	}

	if notFounds >= needSuccesses {
		return nil, true, false
	}

	if len(successResps) >= needSuccesses {
		if keyRead {
			// If we're reading keys, we want all the successes, not
			// the latest.
			return successResps, true, true
		}

		// We have a read quorum. The one with the latest version number
		// (and largest replica ID, in case of a tie) is the right one.
		latestRespIdx := 0

		needsRepairing := []int{}

		for i := range successResps[1:] {
			latestResp := successResps[latestRespIdx]
			sr := successResps[i]

			if sr.Version < latestResp.Version {
				needsRepairing = append(needsRepairing, sr.FromReplica)
				continue
			}

			if sr.Version == latestResp.Version && sr.TID <= latestResp.TID {
				if sr.TID < latestResp.TID {
					needsRepairing = append(needsRepairing, sr.FromReplica)
				}
				continue
			}

			needsRepairing = append(needsRepairing, latestResp.FromReplica)

			latestRespIdx = i
		}

		latestResp := successResps[latestRespIdx]

		// Perform data read repairs in the background. It's OK if these
		// fail. We're just doing our best to update old values we've seen
		// to improve the redundancy of the latest value in the event of a
		// "just-barely" quorum.
		if !keyRead && !digestOnly {
			go func() {
				// We'll initiate all read repairs serially, but in the
				// background, to minutely speed up the return of this request,
				// and we'll queue each read repair in the background to let
				// them work concurrently.
				for _, nr := range needsRepairing {
					// TODO (?): retry RPC failures, but not deterministic failures?
					go func(nr int) {
						latencyMillis := 0
						if fakeLatency {
							latencyMillis = rand.Intn(5000)
						}
						// Like I said, we won't even check for failure.
						// A non-RPC failure just means that there's a newer version,
						// and that's our goal: the newest version, even if it's not
						// ours.
						writeReq(&WriteRequest{
							Version: latestResp.Version,
							// We'll use the original writer's
							// ID to preserve the ordering.
							TID:           latestResp.TID,
							Filename:      filename,
							Data:          latestResp.Data,
							LatencyMillis: latencyMillis,
							Secure:        latestResp.Secure,
						}, nr)
					}(nr)
				}
			}()
		}

		return []*ReadResponse{latestResp}, true, true
	}

	// If we're here, it means that we couldn't achieve a quorum, either
	// due to timeouts or other RPC errors.
	return nil, false, false
}

func (q *QuorumServer) ClientWrite(req *ClientWriteRequest, resp *ClientWriteResponse) error {
	// secure := len(req.KeyPieces) > 0
	secure := req.Secure

	if secure && len(req.KeyPieces) != KEY_REPLICAS {
		return fmt.Errorf("got %d key pieces, but need exactly %d", len(req.KeyPieces), KEY_REPLICAS)
	}

	// Now that we've calculated the write version, we'll try to write to a quorum.
	dataReplicas := replicasForKey(req.Filename, DATA_REPLICAS, q.numReplicas)
	// TODO: make sure countries all have the same key piece.
	keyReplicas := replicasForKey(req.Filename, KEY_REPLICAS, q.numReplicas)

	// fmt.Printf("wreplicas: %+v\n", replicas)

	// Generate a (probably) unique transaction ID for all the writes.
	// If the versions collide (likely), we'll use transaction IDs to break ties.
	// If the versions AND transaction IDs collide but the data differs (HIGHLY unlikely),
	// we can just assume that the data is the same; even hashing it to check would
	// slow down our responses.
	tid := rand.Uint64()
	resp.TID = tid

	// Perform the key writes first. We want them all (or at least a KEY_QUORUM)
	// there before the data gets there so that there's no interval with
	// un-decryptable data.
	if secure {
		keyData := marshalKeyPieces(req.KeyPieces)
		keyWriteResp := q.doWrites(keyReplicas, tid, keyData, req, 0, true, KEY_QUORUM, false)
		switch {
		case keyWriteResp.Overridden:
			return fmt.Errorf("BAD PROBLEM: overridden key write for TID %s", tid64(tid))
		case !keyWriteResp.Success:
			return fmt.Errorf("unsuccessful key write for TID %s; please try again")
		}
	}

	// Now perform the data writes.

	// First, we need to read the digests from all the replicas
	// to get the most recent version number. We'll call our own
	// ClientRead function to do that.
	clientReadReq := &ClientReadRequest{
		Filename:    req.Filename,
		DigestOnly:  true,
		FakeLatency: req.FakeLatency,
	}

	var clientReadResp ClientReadResponse

	if err := q.ClientRead(clientReadReq, &clientReadResp); err != nil {
		return fmt.Errorf("error reading latest version from replicas: %s", err)
	}

	if !clientReadResp.Success {
		return fmt.Errorf("unknown error reaching quorum for latest version from replicas...maybe too many replicas are down?")
	}

	writeVersion := 0
	if clientReadResp.Found {
		// This "+ 1" could be tweaked to be larger
		// if we wanted a higher chance of bullying concurrent
		// writers. It would probably correspond to the number
		// of concurrent writers we're guaranteed to supercede,
		// minus one.
		// TODO: bully value in per-request config
		writeVersion = clientReadResp.Version + 1
	}

	// Now we can actually perform the data writes.
	dataWriteResp := q.doWrites(dataReplicas, tid, req.Data, req, writeVersion, false, WRITE_QUORUM, true)

	resp.Success = dataWriteResp.Success
	resp.Overridden = dataWriteResp.Overridden
	resp.TID = dataWriteResp.TID

	return nil
}

func (q *QuorumServer) doWrites(replicas []int, tid uint64, data []byte, req *ClientWriteRequest, writeVersion int, tagWithTID bool, needSuccesses int, secure bool) *ClientWriteResponse {
	resp := &ClientWriteResponse{
		TID: tid,
	}

	responses := make(chan *WriteResponse, len(replicas))

	selfReplica := false
	for _, replica := range replicas {
		// fmt.Printf("asking replica %d\n", replica)
		if replica == q.replicaID {
			selfReplica = true
			continue
		}

		go func(replica int) {
			latencyMillis := 0
			if req.FakeLatency {
				latencyMillis = rand.Intn(5000)
			}

			// fmt.Printf("sending write request to replica %d\n", replica)

			replicaResp, err := writeReq(&WriteRequest{
				Version:       writeVersion,
				TID:           tid,
				Filename:      req.Filename,
				Data:          data,
				LatencyMillis: latencyMillis,
				TagWithTID:    tagWithTID,
				Secure:        secure,
			}, replica)

			if err != nil {
				fmt.Printf("write RPC error: %s\n", err)
				responses <- nil
				return
			}

			responses <- replicaResp
		}(replica)
	}

	// Handle the case where we're a replica.
	if selfReplica {
		latencyMillis := 0
		if req.FakeLatency {
			latencyMillis = rand.Intn(5000)
		}

		selfWriteReq := &WriteRequest{
			Version:       writeVersion,
			TID:           tid,
			Filename:      req.Filename,
			Data:          data,
			LatencyMillis: latencyMillis,
			TagWithTID:    tagWithTID,
			Secure:        secure,
		}

		var selfWriteResp WriteResponse

		if err := q.Write(selfWriteReq, &selfWriteResp); err != nil {
			responses <- nil
		} else {
			responses <- &selfWriteResp
		}
	}

	rpcFailures := 0
	writeFailures := 0
	successes := 0
	// for replicaResp := range responses {
	for i := 0; i < q.numReplicas; i++ {
		replicaResp := <-responses

		switch {
		case replicaResp == nil:
			rpcFailures++
		case !replicaResp.Success:
			writeFailures++
		default:
			successes++
		}

		if successes >= needSuccesses {
			resp.Success = true
			break
		}

		if (rpcFailures + writeFailures) > (len(replicas) - needSuccesses) {
			if writeFailures > 0 {
				// We lost to someone else writing concurrently.
				resp.Overridden = true
			}

			// Otherwise, all we can say is that it was a
			// transient error.
			break
		}
	}

	return resp
}

func (q *QuorumServer) ClientCryptoReplicas(req *ClientCryptoReplicasRequest, resp *ClientCryptoReplicasResponse) error {
	// Calculate the KEY_REPLICAS replicas for the normal filename.
	// Even though the key filename will be tagged with a TID later,
	// we'll manually make sure that those tags don't change the key's
	// replica set.
	// TODO: make sure of that.

	replicaPubKeys := make(map[int]string)

	replicas := replicasForKey(req.Filename, KEY_REPLICAS, q.numReplicas)
	for _, repl := range replicas {
		pub, ok := q.replicaPubKeys[repl]
		if !ok {
			return fmt.Errorf("don't have a public key for replica %d", pub)
		}

		replicaPubKeys[repl] = string(marshalPublicKey(pub))
	}

	resp.ReplicaPubKeys = replicaPubKeys

	return nil
}
