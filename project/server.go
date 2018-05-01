package project

import (
	// "bufio"
	// "crypto/rsa"
	"fmt"
	"math/rand"
	"net"
	"net/rpc"
	"strconv"
	// "strings"
	"os"
	// "time"
	// sssa "./sssa-golang"
)

func RunServer() {
	if len(os.Args) < 4 {
		fmt.Printf("need an ID argument, a private key, and a filename list of other replicas\n")
		return
	}

	rid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("replica ID argument must be an integer\n")
		return
	}

	rand.Seed(int64(rid))

	priv, err := unMarshalPrivateKey([]byte(os.Args[2]))
	if err != nil {
		fmt.Printf("invalid private key\n")
		return
	}

	addrMap, keyMap := parseReplicas(os.Args[3])

	qs := newQuorumServer(rid, addrMap, keyMap, priv, keyMap[rid])

	server := rpc.NewServer()
	server.Register(qs)

	l, err := net.Listen("tcp", addrMap[rid])
	if err != nil {
		fmt.Printf("listen error: \n", err)
		return
	}

	fmt.Printf("server is up!\n")

	server.Accept(l)
}
