package main

import (
	"github.com/dvshur/distributed-signature/pkg/peer"
	"github.com/dvshur/distributed-signature/pkg/server"
)

func main() {
	p1 := peer.NewLocalPeer()
	p2 := peer.NewLocalPeer()
	p3 := peer.NewLocalPeer()
	c := peer.NewCoordinator([]peer.Peer{p1, p2, p3})

	server.Create(c).Run("0.0.0.0:8080")
}
