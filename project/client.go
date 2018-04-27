package project

import (
	"crypto/rsa"
	"fmt"
	// "log"
	"math/rand"
	// "net"
	// "net/rpc"
	// "time"

	sssa "./sssa-golang"
)

type QuorumClient interface {
	Write(filename string, data []byte) string
	Read(filename string) string
}

type quorumClient struct {
	publicKey *rsa.PublicKey
	privateKey *rsa.PrivateKey

	readNum int

	replicaAddrs []string
}

func NewQuorumClient(replicaAddrs []string) (QuorumClient, error) {
	priv, pub, err := makeRSAKeyPair()
	if err != nil {
		return nil, fmt.Errorf("error making RSA key pair: %s", err)
	}

	return &quorumClient{
		publicKey: pub,
		privateKey: priv,
		replicaAddrs: replicaAddrs,
	}, nil
}

func (c *quorumClient) Write(filename string, data []byte) string {
	// Pick a random replica.
	replicaAddr := c.replicaAddrs[rand.Intn(len(c.replicaAddrs))]

	// First, get the crypto replicas for the file.

	// TODO: actually do this, so we can get the public keys before sending the
	// key pieces to a single, untrusted replica for distribution.
	crResp, err := clientCryptoRepls(&DistCryptoReplicasRequest{
		Filename: filename,
	}, replicaAddr)
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
	resp, err := clientWrite(filename, encryptedData, replicaAddr, true, true, keyPieceMap)
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

func (c *quorumClient) Read(filename string) string {
	// Pick a random replica.
	replicaAddr := c.replicaAddrs[rand.Intn(len(c.replicaAddrs))]

	resp, err := distRead(filename, replicaAddr, false, true, c.publicKey)
	if err != nil {
		return fmt.Sprintf("error reading %s: %s", filename, err)
	}

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
		msg = fmt.Sprintf("yay! read %d for %s is ready to decrypt locally! (version %d, TID %s)", c.readNum, filename, resp.Version, tid64(resp.TID))

		var decryptedKeyPieces []string
		decryptError := false
		for _, ekp := range resp.EncryptedKeyPieces {
			dkp, err := decryptRSA([]byte(ekp), c.privateKey)
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
				decryptedData, err := decrypt(resp.Data, []byte(combinedKey))
				if err != nil {
					msg = msg + fmt.Sprintf("\n\tbut we got an error decrypting the file: %s", err)
				} else {
					msg = msg + fmt.Sprintf("\n\tand the decrypted value is %q", decryptedData)
				}
			}
		}

	default:
		msg = fmt.Sprintf("non-secure yay! read %d for %s is %q (version %d, TID %s)", c.readNum, filename, resp.Data, resp.Version, tid64(resp.TID))
	}

	return msg
}
