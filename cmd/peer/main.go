package main

import (
	"github.com/dvshur/distributed-signature/pkg/aggsig"
	"github.com/dvshur/distributed-signature/pkg/crypto"
)

func main() {
	p1 := aggsig.NewLocalPeer()
	// p2 := aggsig.NewLocalPeer()
	// p3 := aggsig.NewLocalPeer()

	c := aggsig.NewCoordinator([]aggsig.Peer{p1})

	clientID := "vasya"

	pk, err := c.Keygen(clientID)
	if err != nil {
		panic(err)
	}

	message := []byte{1, 2, 3}

	sig, err := c.Sign(clientID, message)
	if err != nil {
		panic(err)
	}

	if crypto.Verify(pk, sig, message) {
		println("Cool, verified")
	} else {
		println("Failed")
	}
}
