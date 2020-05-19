package main

import (
	"distributed-sig/crypto/aggsig"

	"github.com/wavesplatform/gowaves/pkg/crypto"
)

func main() {
	p1 := aggsig.NewLocalPeer()
	p2 := aggsig.NewLocalPeer()
	p3 := aggsig.NewLocalPeer()

	c := aggsig.NewCoordinator([]aggsig.Peer{p1, p2, p3})

	clientID := "vasya"

	pk, err := c.Keygen(clientID)
	if err != nil {
		panic(err)
	}

	message := []byte{1, 2, 3, 4}

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