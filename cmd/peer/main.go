package main

import (
	"github.com/dvshur/distributed-signature/pkg/peer"
	"github.com/dvshur/distributed-signature/pkg/server"
)

func main() {
	// 1 peer coordinator works
	p1 := peer.NewLocalPeer()
	c := peer.NewCoordinator([]peer.Peer{p1})

	server.Create(c).Run("0.0.0.0:8080")

	// pk, err := c.Keygen(clientID)
	// if err != nil {
	// 	panic(err)
	// }

	// var sig crypto.Signature
	// for {
	// 	sig, err = c.Sign(clientID, message)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	if crypto.Verify(pk, sig, message) {
	// 		break
	// 	}
	// }

	// sig, err := c.Sign(clientID, message)
	// if err != nil {
	// 	panic(err)
	// }

	// if crypto.Verify(pk, sig, message) {
	// 	println("Cool, verified")
	// } else {
	// 	println("Failed")
	// }
}
