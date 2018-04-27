package project

import (
	"bufio"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"strings"
	"time"
	"os"
)

func parseReplicas(filename string) (map[int]string, map[int]*rsa.PublicKey) {
	addrMap := make(map[int]string)
	keyMap := make(map[int]*rsa.PublicKey)

	f, err := os.Open(filename)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	idx := 0
	for scanner.Scan() {
		line := scanner.Text()
		spl := strings.Split(line, " ")
		addr := spl[0]
		key, err := unMarshalPublicKey([]byte(spl[1]))
		if err != nil {
			panic(err)
		}

		addrMap[idx] = addr
		keyMap[idx] = key

		idx++
	}

	return addrMap, keyMap
}

func RunClient() {
	if len(os.Args) < 2 {
		fmt.Printf("need a list of replicas & their keys\n")
	}

	addrMap, _ := parseReplicas(os.Args[1])

	var addrList []string
	for i := 0; i < len(addrMap); i++ {
		addrList = append(addrList, addrMap[i])
	}

	qc, err := NewQuorumClient(addrList)
	if err != nil {
		fmt.Printf("error making client: %s", err)
		return
	}

	go func() {
		// for i := 0; i < 10; i++ {
		for {
			fmt.Println(qc.Write("test1", []byte(fmt.Sprintf("conflict%d", rand.Intn(10)))))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		// for i := 0; i < iters; i++ {
		for {
			fmt.Println(qc.Write("test1", []byte(fmt.Sprintf("conflict%d", rand.Intn(10)))))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		// for i := 0; i < iters; i++ {
		for {
			fmt.Println(qc.Write("test1", []byte(fmt.Sprintf("conflict%d", rand.Intn(10)))))
			time.Sleep(1000 + time.Duration(rand.Intn(3000))*time.Millisecond)
		}
	}()

	go func() {
		for {
			time.Sleep(500 * time.Millisecond)
			fmt.Printf("\n%s\n\n", qc.Read("test1"))
		}
	}()

	select {}
}
