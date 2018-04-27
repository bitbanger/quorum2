package main

import (
	// "fmt"

	"../project"
)

func main() {
	// project.Test()
	/*for i := 0; i < 32; i++ {
		priv, pub, _ := project.MakeRSAKeyPair()
		fmt.Printf("localhost:%d %s\n%s\n", 1234+i, project.MarshalPublicKey(pub), project.MarshalPrivateKey(priv))
	}*/

	project.RunClient()
}
