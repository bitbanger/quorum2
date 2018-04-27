package project

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/rand"
	"net"
	"net/rpc"
	"strconv"
	"strings"
)

func clientRead(filename string, replicaAddr string, digestOnly bool, latency bool, clientPubKey *rsa.PublicKey) (*ClientReadResponse, error) {
	conn, err := net.Dial("tcp", replicaAddr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to replica %s: %s", replicaAddr, err)
	}

	client := rpc.NewClient(conn)

	req := &ClientReadRequest{
		Filename:        filename,
		DigestOnly:      digestOnly,
		FakeLatency:     latency,
		ClientPublicKey: marshalPublicKey(clientPubKey),
	}

	var resp ClientReadResponse

	if err = client.Call("QuorumServer.ClientRead", req, &resp); err != nil {
		return nil, fmt.Errorf("error calling client read method on replica %s: %s", replicaAddr, err)
	}

	return &resp, nil
}

func clientWrite(filename string, data []byte, replicaAddr string, latency bool, secure bool, keyPieces map[int]string) (*ClientWriteResponse, error) {
	conn, err := net.Dial("tcp", replicaAddr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to replica %d: %s", replicaAddr, err)
	}

	client := rpc.NewClient(conn)

	req := &ClientWriteRequest{
		Filename:    filename,
		Data:        data,
		FakeLatency: latency,
		Secure:      secure,
		KeyPieces:   keyPieces,
	}

	var resp ClientWriteResponse

	if err = client.Call("QuorumServer.ClientWrite", req, &resp); err != nil {
		return nil, fmt.Errorf("error calling client write method on replica %d: %s", replicaAddr, err)
	}

	return &resp, nil
}

func clientCryptoRepls(req *ClientCryptoReplicasRequest, replicaAddr string) (*ClientCryptoReplicasResponse, error) {
	conn, err := net.Dial("tcp", replicaAddr)
	if err != nil {
		return nil, fmt.Errorf("error connecting to replica %d: %s", replicaAddr, err)
	}

	client := rpc.NewClient(conn)

	var resp ClientCryptoReplicasResponse

	if err = client.Call("QuorumServer.ClientCryptoReplicas", req, &resp); err != nil {
		return nil, fmt.Errorf("error calling crypto replicas method on replica %d: %s", replicaAddr, err)
	}

	return &resp, nil
}

func uint64Bytes(n uint64) []byte {
	bs := []byte{0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 8; i++ {
		shift := uint(56 - (i * 8))
		bs[i] = byte(n >> shift & 255)
	}

	return bs
}

func tid64(tid uint64) string {
	return base64.StdEncoding.EncodeToString(uint64Bytes(tid))
}

func readReq(req *ReadRequest, replicaID int) (*ReadResponse, error) {
	conn, err := net.Dial("tcp", replicaAddress(replicaID))
	if err != nil {
		return nil, fmt.Errorf("error connecting to replica %d: %s", replicaID, err)
	}

	client := rpc.NewClient(conn)

	var resp ReadResponse

	if err = client.Call("QuorumServer.Read", req, &resp); err != nil {
		return nil, fmt.Errorf("error calling read method on replica %d: %s", replicaID, err)
	}

	return &resp, nil
}

func writeReq(req *WriteRequest, replicaID int) (*WriteResponse, error) {
	conn, err := net.Dial("tcp", replicaAddress(replicaID))
	if err != nil {
		return nil, fmt.Errorf("error connecting to replica %d: %s", replicaID, err)
	}

	client := rpc.NewClient(conn)

	var resp WriteResponse

	if err = client.Call("QuorumServer.Write", req, &resp); err != nil {
		return nil, fmt.Errorf("error calling write method on replica %d: %s", replicaID, err)
	}

	return &resp, nil
}

func marshalKeyPieces(keyPieces map[int]string) []byte {
	var buf bytes.Buffer

	firstLine := true
	for k, v := range keyPieces {
		if firstLine {
			firstLine = false
		} else {
			fmt.Fprintf(&buf, "\n")
		}

		b64piece := base64.StdEncoding.EncodeToString([]byte(v))

		fmt.Fprintf(&buf, "%d %s", k, b64piece)
	}

	// fmt.Printf("final marshal: %s\n", buf.Bytes())

	return buf.Bytes()
}

func unmarshalKeyPieces(bs []byte) (map[int]string, error) {
	keyPieces := make(map[int]string)

	for _, l := range strings.Split(string(bs), "\n") {
		sp := strings.Split(l, " ")
		if len(sp) != 2 {
			// fmt.Printf("line: %s\n", l)
			return nil, fmt.Errorf("invalid key piece map encoding: line format was wrong")
		}
		replica, err := strconv.Atoi(sp[0])
		if err != nil {
			// fmt.Printf("line: %s\n", l)
			return nil, fmt.Errorf("invalid key piece map encoding: error decoding replica ID from an int: %s", err)
		}

		encryptedKeyPiece, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sp[1]))
		if err != nil {
			// fmt.Printf("line: %s\n", l)
			return nil, fmt.Errorf("invalid key piece map encoding: error decoding encrypted key piece from base64: %s", err)
		}

		/*if !sssa.IsValidShare(keyPiece) {
			return nil, fmt.Errorf("invalid key piece map encoding: key piece is not a valid SSSA share")
		}*/

		keyPieces[replica] = string(encryptedKeyPiece)
	}

	return keyPieces, nil
}

// replicasForKey returns a deterministic set of min(n, m) (out of m total)
// replicas for a given key. The sharding should be roughly random.
func replicasForKey(key string, n, m int) []int {
	bound := n
	if n > m {
		bound = m
	}

	hash := sha256.Sum256([]byte(key))

	var seed int64
	for i := 0; i < 8; i++ {
		seed = (seed << 8) | int64(hash[i])
	}

	rng := rand.New(rand.NewSource(seed))

	return rng.Perm(m)[:bound]
}

// replicaAddress converts a replica number into a fully qualified network address.
func replicaAddress(n int) string {
	// For now, it's all local.
	return fmt.Sprintf("localhost:%d", 1234+n)
}

// replicaPort converts a replica number into a port.
func replicaPort(n int) string {
	return fmt.Sprintf("%d", 1234+n)
}
