package main

import (
	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/peer"
)

func main() {
	p1 := peer.NewLocalPeer()
	p2 := peer.NewLocalPeer()
	// p3 := peer.NewLocalPeer()

	c := peer.NewCoordinator([]peer.Peer{p1, p2})

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
