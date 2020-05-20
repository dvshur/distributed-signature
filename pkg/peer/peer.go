package peer

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"fmt"
	"sync"

	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/cryptobase"
)

// Peer ..
type Peer interface {
	Ai(clientID string) (*cryptobase.ExtendedGroupElement, error)
	Ri(clientID string, sessionID string, message []byte) (*cryptobase.ExtendedGroupElement, error)
	Si(clientID string, sessionID string, k [32]byte) (*cryptobase.FieldElement, error)
}

type keyPair struct {
	SecretKey [32]byte
	Ai        cryptobase.ExtendedGroupElement
}

// PeerLocal ..
type PeerLocal struct {
	keys       map[string]keyPair
	sessionsRi map[string][32]byte
	mux        sync.RWMutex
}

// NewLocalPeer ..
func NewLocalPeer() Peer {
	return &PeerLocal{
		keys:       make(map[string]keyPair),
		sessionsRi: make(map[string][32]byte),
		mux:        sync.RWMutex{},
	}
}

// Ai ..
func (p *PeerLocal) Ai(clientID string) (*cryptobase.ExtendedGroupElement, error) {
	p.mux.RLock()
	kp, ok := p.keys[clientID]
	p.mux.RUnlock()

	if ok {
		return &kp.Ai, nil
	}

	// generate secret key
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		return nil, err
	}
	sk := [32]byte(crypto.GenerateSecretKey(seed))

	var Ai cryptobase.ExtendedGroupElement
	cryptobase.GeScalarMultBase(&Ai, &sk)

	kp.Ai = Ai
	kp.SecretKey = sk

	p.mux.Lock()
	p.keys[clientID] = kp
	p.mux.Unlock()

	return &Ai, nil
}

// Ri ..
func (p *PeerLocal) Ri(clientID string, sessionID string, message []byte) (*cryptobase.ExtendedGroupElement, error) {
	p.mux.RLock()
	kp, clientExists := p.keys[clientID]
	p.mux.RUnlock()

	if !clientExists {
		return nil, fmt.Errorf("client id %s does not exist", clientID)
	}

	p.mux.RLock()
	ri, sessionExists := p.sessionsRi[sessionID]
	p.mux.RUnlock()

	if !sessionExists {
		var prefix = bytes.Repeat([]byte{0xff}, 32)
		prefix[0] = 0xfe

		random := make([]byte, 64)
		_, err := rand.Read(random)
		if err != nil {
			return nil, err
		}

		var rHash [64]byte
		h := sha512.New()
		if _, err := h.Write(prefix); err != nil {
			return nil, err
		}
		if _, err := h.Write(kp.SecretKey[:]); err != nil {
			return nil, err
		}
		if _, err := h.Write(message); err != nil {
			return nil, err
		}
		if _, err := h.Write(random[:]); err != nil {
			return nil, err
		}
		h.Sum(rHash[:0])

		cryptobase.ScReduce(&ri, &rHash)

		p.mux.Lock()
		p.sessionsRi[sessionID] = ri
		p.mux.Unlock()

		// todo set a goroutine for deleting
	}

	var Ri cryptobase.ExtendedGroupElement
	cryptobase.GeScalarMultBase(&Ri, &ri)

	return &Ri, nil
}

// Si ..
func (p *PeerLocal) Si(clientID string, sessionID string, k [32]byte) (*cryptobase.FieldElement, error) {
	p.mux.RLock()
	kp, clientExists := p.keys[clientID]
	p.mux.RUnlock()

	if !clientExists {
		return nil, fmt.Errorf("client id %s does not exist", clientID)
	}

	p.mux.RLock()
	ri, sessionExists := p.sessionsRi[sessionID]
	p.mux.RUnlock()
	if !sessionExists {
		return nil, fmt.Errorf("session id %s does not exist", sessionID)
	}

	var s [32]byte
	cryptobase.ScMulAdd(&s, &k, &kp.SecretKey, &ri)

	var S cryptobase.FieldElement
	cryptobase.FeFromBytes(&S, &s)

	return &S, nil
}
