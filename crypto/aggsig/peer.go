package aggsig

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"sync"

	"distributed-sig/crypto"
	"distributed-sig/crypto/internal"
)

// Peer ..
type Peer interface {
	Ai(clientID string) (*internal.ExtendedGroupElement, error)
	Ri(clientID string, sessionID string, message []byte) (*internal.ExtendedGroupElement, error)
	Si(clientID string, sessionID string, k [32]byte) (*internal.FieldElement, error)
}

type keyPair struct {
	SecretKey [32]byte
	Ai        internal.ExtendedGroupElement
}

// PeerLocal ..
type PeerLocal struct {
	keys       map[string]keyPair
	sessionsRi map[string][32]byte
	mux        sync.Mutex
}

func NewLocalPeer() Peer {
	return &PeerLocal{
		keys:       make(map[string]keyPair),
		sessionsRi: make(map[string][32]byte),
		mux:        sync.Mutex{},
	}
}

// Ai ..
func (p *PeerLocal) Ai(clientID string) (*internal.ExtendedGroupElement, error) {
	if kp, ok := p.keys[clientID]; ok {
		return &kp.Ai, nil
	} else {
		sk, err := randomKey()

		if err != nil {
			return nil, err
		}
		var Ai internal.ExtendedGroupElement
		internal.GeScalarMultBase(&Ai, &sk)

		kp.Ai = Ai
		kp.SecretKey = sk

		p.mux.Lock()
		p.keys[clientID] = kp
		p.mux.Unlock()

		return &Ai, nil
	}
}

// Ri ..
// todo do I need a mutex lock for reads?
// assuming for now that I don't
func (p *PeerLocal) Ri(clientID string, sessionID string, message []byte) (*internal.ExtendedGroupElement, error) {
	kp, clientExists := p.keys[clientID]

	if !clientExists {
		return nil, errors.New(fmt.Sprint("client id %s does not exist", clientID))
	}

	ri, sessionExists := p.sessionsRi[sessionID]

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

		var r [32]byte
		internal.ScReduce(&r, &rHash)

		p.mux.Lock()
		p.sessionsRi[sessionID] = ri
		p.mux.Unlock()

		// todo set a goroutine for deleting
	}

	var Ri internal.ExtendedGroupElement
	internal.GeScalarMultBase(&Ri, &ri)

	return &Ri, nil
}

// Si ..
func (p *PeerLocal) Si(clientID string, sessionID string, k [32]byte) (*internal.FieldElement, error) {
	kp, clientExists := p.keys[clientID]
	if !clientExists {
		return nil, errors.New(fmt.Sprint("client id %s does not exist", clientID))
	}

	ri, sessionExists := p.sessionsRi[sessionID]
	if !sessionExists {
		return nil, errors.New(fmt.Sprint("session id %s does not exist", sessionID))
	}

	var s [32]byte
	internal.ScMulAdd(&s, &k, &kp.SecretKey, &ri)

	var S internal.FieldElement
	internal.FeFromBytes(&S, &s)

	return &S, nil
}

func randomKey() ([crypto.SecretKeySize]byte, error) {
	var sk crypto.SecretKey

	sk1 := make([]byte, 32)
	_, err := rand.Read(sk1)
	if err != nil {
		return sk, err
	}

	copy(sk[:], sk1)
	return sk, nil
}
