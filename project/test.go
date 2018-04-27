package project

import (
	"crypto/rsa"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/rpc"
	"time"

	sssa "./sssa-golang"
)

func makeServer(quorum *QuorumServer, serverUpChan chan bool) {
	// var quorum Quorum = newQuorumServer(replicaID, numReplicas)

	server := rpc.NewServer()
	server.Register(quorum)

	l, e := net.Listen("tcp", fmt.Sprintf(":%s", replicaPort(quorum.replicaID)))
	if e != nil {
		log.Fatal("listen error: ", e)
	}

	serverUpChan <- true

	server.Accept(l)
}

var quora []*QuorumServer

func Test() {
	numServers := 16

	fmt.Printf("write quorum: %d\n", WRITE_QUORUM)
	fmt.Printf("read quorum: %d\n", READ_QUORUM)

	/*for _, m := range []string{"hey", "", "no problem!", "once a long long time ago I strived to meet the AES block size", "0123456789ABCDEF"} {
		msg := []byte(m)
		key, err := makeKey()
		if err != nil {
			fmt.Printf("key err: %s\n", err)
		} else {
			enc, err := encrypt(msg, key)
			if err != nil {
				fmt.Printf("enc err: %s\n", err)
			} else {
				dec, err := decrypt(enc, key)
				if err != nil {
					fmt.Printf("dec err: %s\n", err)
				} else {
					fmt.Printf("decrypted message: %q\n", dec)
				}
			}
		}
	}*/

	serverUpChan := make(chan bool, numServers)

	serverPubKeys := make(map[int]*rsa.PublicKey)
	serverPrivKeys := make(map[int]*rsa.PrivateKey)
	for i := 0; i < numServers; i++ {
		priv, pub, err := makeRSAKeyPair()
		if err != nil {
			fmt.Printf("main thread stopping: %s\n", err)
			return
		}

		serverPubKeys[i] = pub
		serverPrivKeys[i] = priv
	}

	// Run some servers in the background.
	for i := 0; i < numServers; i++ {
		quorum := newQuorumServer(i, numServers, serverPubKeys, serverPrivKeys[i], serverPubKeys[i])
		quora = append(quora, quorum)

		go makeServer(quorum, serverUpChan)
	}

	// Wait for the servers to be up before we make any requests.
	for i := 0; i < numServers; i++ {
		<-serverUpChan
	}

	// All servers are now running in the background.
	// Let's make some test requests as the client.

	clientPriv, clientPub, err := makeRSAKeyPair()
	if err != nil {
		fmt.Printf("main thread stopping: %s\n", err)
		return
	}

	/*mPriv := string(marshalPrivateKey(clientPriv))
	mPub := string(marshalPublicKey(clientPub))
	priv, err := unmarshalPrivateKey([]byte(mPriv))
	if err != nil {
		fmt.Printf("main thread stopping: %s\n", err)
		return
	}
	pub, err := unmarshalPublicKey([]byte(mPub))
	if err != nil {
		fmt.Printf("main thread stopping: %s\n", err)
		return
	}

	enc, err := encryptRSA([]byte("hi there!"), pub)
	if err != nil {
		fmt.Printf("main thread stopping: %s\n", err)
		return
	}

	fmt.Printf("enc: %s\n", string(enc))

	dec, err := decryptRSA(enc, priv)
	if err != nil {
		fmt.Printf("main thread stopping: %s\n", err)
		return
	}

	fmt.Printf("dec: %s\n", string(dec))*/

	go func() {
		// for i := 0; i < 10; i++ {
		for {
			fmt.Println(easyWrite("test1", fmt.Sprintf("conflict%d", rand.Intn(10)), rand.Intn(numServers)))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		// for i := 0; i < iters; i++ {
		for {
			fmt.Println(easyWrite("test1", fmt.Sprintf("conflict%d", rand.Intn(10)), rand.Intn(numServers)))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		// for i := 0; i < iters; i++ {
		for {
			fmt.Println(easyWrite("test1", fmt.Sprintf("conflict%d", rand.Intn(10)), rand.Intn(numServers)))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			fmt.Printf("\n%s\n\n", easyRead("test1", rand.Intn(numServers), clientPub, clientPriv))
		}
	}()

	select {}
}

func easyWrite(filename string, data string, replicaID int) string {
	// First, get the crypto replicas for the file.

	// TODO: actually do this, so we can get the public keys before sending the
	// key pieces to a single, untrusted replica for distribution.
	crResp, err := clientCryptoRepls(&ClientCryptoReplicasRequest{
		Filename: filename,
	}, replicaID)
	if err != nil {
		return fmt.Sprintf("error getting crypto replica keys for %s: %s", filename, err)
	}

	rpks := crResp.ReplicaPubKeys
	if len(rpks) != KEY_REPLICAS {
		return fmt.Sprintf("wanted to get back %d replica keys for the filename, but got %d", KEY_REPLICAS, len(rpks))
	}

	// Then, calculate key pieces.

	aesKey, err := makeKey()
	if err != nil {
		return fmt.Sprintf("error making AES key: %s", err)
	}

	encryptedData, err := encrypt([]byte(data), aesKey)
	if err != nil {
		return fmt.Sprintf("error encrypting data: %s", err)
	}

	keyPieces, err := sssa.Create(KEY_QUORUM, len(rpks), string(aesKey))
	if err != nil {
		return fmt.Sprintf("error calculating key pieces for %s: %s", filename, err)
	}

	keyPieceMap := make(map[int]string)
	keyPieceIdx := 0
	for repl, pubStr := range rpks {
		pubKey, err := unmarshalPublicKey([]byte(pubStr))
		if err != nil {
			return fmt.Sprintf("error unmarshaling public key: %s", err)
		}

		encKeyPiece, err := encryptRSA([]byte(keyPieces[keyPieceIdx]), pubKey)
		if err != nil {
			return fmt.Sprintf("error encrypting key piece: %s", err)
		}

		keyPieceMap[repl] = string(encKeyPiece)

		keyPieceIdx++
	}

	// Now do the write.
	resp, err := clientWrite(filename, encryptedData, replicaID, true, true, keyPieceMap)
	if err != nil {
		return fmt.Sprintf("error writing (%s, %q): %s", filename, data, err)
	}

	if resp.Overridden {
		return fmt.Sprintf("write %s for (%s, %q) was overridden by a concurrent write", tid64(resp.TID), filename, data)
	}

	if !resp.Success {
		return fmt.Sprintf("write %s for (%s, %q) failed transiently", tid64(resp.TID), filename, data)
	}

	return fmt.Sprintf("write %s for (%s, %q) succeeded!", tid64(resp.TID), filename, data)
}

var readNum int

func easyRead(filename string, replicaID int, clientPub *rsa.PublicKey, clientPriv *rsa.PrivateKey) string {
	readNum++
	/*groundTruth := []string{}
	for _, q := range quora {
		lock := q.getFileLock(filename)
		lock.RLock()
		item, ok := q.storage[filename]
		lock.RUnlock()
		if !ok {
			groundTruth = append(groundTruth, "")
		} else {
			groundTruth = append(groundTruth, string(item.Data))
		}
	}

	var gtStr string
	for i, gt := range groundTruth {
		if i > 0 {
			gtStr = gtStr + ", "
		}
		gtStr = gtStr + gt
	}

	fmt.Printf("\n\nGROUND TRUTH: %s\n\n", gtStr)*/

	fmt.Printf("starting read #%d\n", readNum)
	resp, err := clientRead(filename, replicaID, false, true, clientPub)
	if err != nil {
		return fmt.Sprintf("error reading %s: %s", filename, err)
	}

	/*if resp.Success && !resp.Found {
		return fmt.Sprintf("no possible quorum could find %s", filename)
	}

	if resp.Success {
		return fmt.Sprintf("yay! read %d for %s is %q (version %d, TID %s)", readNum, filename, resp.Data, resp.Version, tid64(resp.TID))
	}

	return fmt.Sprintf("read for %s failed transiently", filename)*/

	var msg string

	switch {
	case !resp.Success:
		msg = fmt.Sprintf("read for %s failed transiently", filename)
	case resp.Success && !resp.Found:
		msg = fmt.Sprintf("no possible quorum could find %s", filename)
	case resp.Secure && !resp.KeySuccess:
		msg = fmt.Sprintf("crypto read for %s failed transiently", filename)
	case resp.Secure && resp.KeySuccess && !resp.KeyFound:
		msg = fmt.Sprintf("no possible crypto quorum could find %s", filename)
	case resp.Secure:
		msg = fmt.Sprintf("yay! read %d for %s is ready to decrypt locally! (version %d, TID %s)", readNum, filename, resp.Version, tid64(resp.TID))
		// msg = msg + fmt.Sprintf("\n\tand key pieces are %+v", readNum, filename, resp.Data, resp.Version, tid64(resp.TID), resp.EncryptedKeyPieces)

		var decryptedKeyPieces []string
		decryptError := false
		for _, ekp := range resp.EncryptedKeyPieces {
			dkp, err := decryptRSA([]byte(ekp), clientPriv)
			if err != nil {
				decryptError = true
				msg = msg + fmt.Sprintf("\n\tbut we got an error decrypting a key piece: %s", err)
			}

			decryptedKeyPieces = append(decryptedKeyPieces, string(dkp))
		}

		if !decryptError {
			combinedKey, err := sssa.Combine(decryptedKeyPieces)
			if err != nil {
				msg = msg + fmt.Sprintf("\n\tbut we got an error combining the decrypted key pieces: %s", err)
				msg = msg + fmt.Sprintf("\n\tkey pieces: %+v", decryptedKeyPieces)
			} else {
				// msg = msg + fmt.Sprintf("\n\tand the combined key is %s", combinedKey)
				decryptedData, err := decrypt(resp.Data, []byte(combinedKey))
				if err != nil {
					msg = msg + fmt.Sprintf("\n\tbut we got an error decrypting the file: %s", err)
				} else {
					msg = msg + fmt.Sprintf("\n\tand the decrypted value is %q", decryptedData)
				}
			}
		}

	default:
		msg = fmt.Sprintf("non-secure yay! read %d for %s is %q (version %d, TID %s)", readNum, filename, resp.Data, resp.Version, tid64(resp.TID))
	}

	return msg
}
