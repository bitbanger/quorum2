package project

import (
	"bufio"
	"crypto/rsa"
	"fmt"
	"math/rand"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	LATENCY_BASE = 500

	LATENCY_SCALE = 1500

	WRITERS = 20

	READERS = 5
)

var (
	lastWrite int64

	writes     map[uint64]int64
	writesLock *sync.RWMutex

	totalReads  int
	totalWrites int
	overridden  int
	successes   int
	futureReads int
	olderReads  int
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

func write(qc QuorumClient) {
	// rt := time.Now().UnixNano()

	// fmt.Printf("write %d starting\n", rt)

	time.Sleep(LATENCY_BASE + time.Duration(rand.Intn(LATENCY_SCALE))*time.Millisecond)

	resp, err := qc.Write("test1", []byte(fmt.Sprintf("conflict%d", rand.Intn(10))))
	if err != nil {
		// fmt.Printf("write %d returned error: %v\n", rt, err)
		return
	}

	if resp.Overridden {
		overridden++
	}

	if !resp.Success {
		return
	}

	// fmt.Printf("write TID %s done\n", tid64(resp.TID))

	tid := resp.TID

	wt := time.Now().UnixNano()

	writesLock.Lock()
	writes[tid] = wt
	writesLock.Unlock()

	for {
		if last := atomic.LoadInt64(&lastWrite); wt < last || atomic.CompareAndSwapInt64(&lastWrite, last, wt) {
			break
		}
	}

	// fmt.Printf("write %d succeeded!\n", rt)
}

func read(qc QuorumClient) {
	rt := time.Now().UnixNano()

	// fmt.Printf("read %d starting\n", rt)

	lw := atomic.LoadInt64(&lastWrite)

	time.Sleep(LATENCY_BASE + time.Duration(rand.Intn(LATENCY_SCALE))*time.Millisecond)
	resp, err := qc.Read("test1")
	if err != nil {
		fmt.Printf("read %d returned error: %v\n", rt, err)
		return
	}
	if !resp.Success {
		return
	}

	writesLock.RLock()
	rt, ok := writes[resp.TID]
	writesLock.RUnlock()
	if !ok {
		// We got a write before it was "fully" registered as a success.
		// That's fine.
		futureReads++
		successes++
		fmt.Printf("Read %d got up-to-date value %q\n", rt, resp.Data)
		return
	}

	if rt < lw {
		olderReads++
		// fmt.Printf("Read %d got old TID %s\n", rt, tid64(resp.TID))
		// fmt.Printf("Read value older than last write before read! :(\n")
		return
	}

	successes++
	fmt.Printf("Read %d got up-to-date value %q\n", rt, resp.Data)

	// fmt.Printf("read %d returned value %q\n", rt, resp.Data)
}

func RunClient() {
	if len(os.Args) < 2 {
		// fmt.Printf("need a list of replicas & their keys\n")
	}

	writes = make(map[uint64]int64)
	writesLock = &sync.RWMutex{}

	addrMap, _ := parseReplicas(os.Args[1])

	var addrList []string
	for i := 0; i < len(addrMap); i++ {
		addrList = append(addrList, addrMap[i])
	}

	qc, err := NewQuorumClient(addrList)
	if err != nil {
		// fmt.Printf("error making client: %s", err)
		return
	}

	for i := 0; i < WRITERS; i++ {
		go func() {
			for {
				write(qc)
				totalWrites++
			}
		}()
	}

	// Wait for some writes to happen before we start reading.
	time.Sleep(5*time.Second)

	for i := 0; i < READERS; i++ {
		go func() {
			for {
				read(qc)
				totalReads++
			}
		}()
	}

	go func() {
		for {
			time.Sleep(5 * time.Second)
			fmt.Printf("total reads: %d\ntotal writes: %d\n\nconcurrent writes overridden: %d\nreads from the future (also successes): %d\nreads with stale values (should be 0): %d\nread successes: %d\n", totalReads, totalWrites, overridden, futureReads, olderReads, successes)
		}
	}()

	select {}
}
