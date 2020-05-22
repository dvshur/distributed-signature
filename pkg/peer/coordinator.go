package peer

import (
	"crypto/sha512"
	"fmt"
	"math/rand" // not for crypto purposes
	"sync"

	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/cryptobase"
)

// Coordinator ..
type Coordinator interface {
	Keygen(clientID string) (crypto.PublicKey, error)
	Sign(clientID string, message []byte) (crypto.Signature, error)
	GetPublicKey(clientID string) (crypto.PublicKey, bool) // todo error
}

// CoordinatorImpl ..
type CoordinatorImpl struct {
	peers     []Peer
	pubKeysEd map[string]cryptobase.ExtendedGroupElement
	mux       sync.RWMutex
}

// NewCoordinator ..
func NewCoordinator(peers []Peer) Coordinator {
	return &CoordinatorImpl{
		peers:     peers,
		pubKeysEd: make(map[string]cryptobase.ExtendedGroupElement),
		mux:       sync.RWMutex{},
	}
}

// GetPublicKey ..
func (c *CoordinatorImpl) GetPublicKey(clientID string) (crypto.PublicKey, bool) {
	c.mux.RLock()
	A, ok := c.pubKeysEd[clientID]
	c.mux.RUnlock()
	return curvePKFromEdPK(&A), ok
}

// Keygen ..
func (c *CoordinatorImpl) Keygen(clientID string) (crypto.PublicKey, error) {
	pk, clientExists := c.GetPublicKey(clientID)
	if clientExists {
		return pk, nil
	}

	errors := make(chan error)
	AA := make(chan cryptobase.ExtendedGroupElement)

	// get all peers Ai
	for _, p := range c.peers {
		go func(p Peer) {
			Ai, err := p.Ai(clientID)
			if err != nil {
				errors <- err
				return
			}
			AA <- *Ai
		}(p)
	}
	As := make([]cryptobase.ExtendedGroupElement, len(c.peers))
	for i := range c.peers {
		select {
		case Ai := <-AA:
			As[i] = Ai
		case err := <-errors:
			return pk, err
		}
	}
	A := sumGe(As)

	c.mux.Lock()
	c.pubKeysEd[clientID] = A
	c.mux.Unlock()

	return curvePKFromEdPK(&A), nil
}

// sumFEModL ...
func sumFEModL(elements []*cryptobase.FieldElement) cryptobase.FieldElement {
	var SByte [32]byte
	var SiByte [32]byte

	var one [32]byte
	one[0] = 1

	for _, Si := range elements {
		cryptobase.FeToBytes(&SiByte, Si)
		cryptobase.ScMulAdd(&SByte, &one, &SByte, &SiByte)
	}

	var S cryptobase.FieldElement
	cryptobase.FeFromBytes(&S, &SByte)
	return S
}

// Sign ..
func (c *CoordinatorImpl) Sign(clientID string, message []byte) (crypto.Signature, error) {
	var signature crypto.Signature

	c.mux.RLock()
	A, clientExists := c.pubKeysEd[clientID]
	c.mux.RUnlock()
	if !clientExists {
		return signature, fmt.Errorf("client id %s does not exist", clientID)
	}

	errors := make(chan error)
	sessionID := randomSessionID()

	// phase1: ask peers for R_i to calculate R
	RR := make(chan cryptobase.ExtendedGroupElement)
	for _, p := range c.peers {
		go func(p Peer) {
			Ri, err := p.Ri(clientID, sessionID, message)
			if err != nil {
				errors <- err
				return
			}
			RR <- *Ri
		}(p)
	}
	Rs := make([]cryptobase.ExtendedGroupElement, len(c.peers))
	for i := range c.peers {
		select {
		case Ri := <-RR:
			Rs[i] = Ri
		case err := <-errors:
			return signature, err
		}
	}
	R := sumGe(Rs)

	k, err := calculateK(&R, &A, message)
	if err != nil {
		return signature, err
	}

	// phase 2: ask peers for S_i to calculate S
	SS := make(chan cryptobase.FieldElement)
	for _, p := range c.peers {
		go func(p Peer) {
			Si, err := p.Si(clientID, sessionID, k)
			if err != nil {
				errors <- err
				return
			}
			SS <- *Si
		}(p)
	}
	Ss := make([]*cryptobase.FieldElement, len(c.peers))
	for i := range c.peers {
		select {
		case Si := <-SS:
			Ss[i] = &Si
		case err := <-errors:
			return signature, err
		}
	}
	S := sumFEModL(Ss)

	// serialize R, S to bytes — ed25519 signature
	var RByte, SByte [32]byte
	R.ToBytes(&RByte)
	cryptobase.FeToBytes(&SByte, &S)
	copy(signature[:], RByte[:])
	copy(signature[32:], SByte[:])

	// ed25519 to curve25519 signature
	var publicKeyEd = new([crypto.PublicKeySize]byte)
	A.ToBytes(publicKeyEd)
	signBit := publicKeyEd[31] & 0x80

	signature[63] &= 0x7f
	signature[63] |= signBit

	return signature, nil
}

func sumGe(ges []cryptobase.ExtendedGroupElement) cryptobase.ExtendedGroupElement {
	var res cryptobase.ExtendedGroupElement
	for i, ge := range ges {
		if i == 0 {
			res = ge
		} else {
			cryptobase.GeAdd(&res, &res, &ge)
		}
	}
	return res
}

func curvePKFromEdPK(ed *cryptobase.ExtendedGroupElement) crypto.PublicKey {
	var pk crypto.PublicKey
	var edYPlusOne = new(cryptobase.FieldElement)
	cryptobase.FeAdd(edYPlusOne, &ed.Y, &ed.Z)
	var oneMinusEdY = new(cryptobase.FieldElement)
	cryptobase.FeSub(oneMinusEdY, &ed.Z, &ed.Y)
	var invOneMinusEdY = new(cryptobase.FieldElement)
	cryptobase.FeInvert(invOneMinusEdY, oneMinusEdY)
	var montX = new(cryptobase.FieldElement)
	cryptobase.FeMul(montX, edYPlusOne, invOneMinusEdY)
	p := new([crypto.PublicKeySize]byte)
	cryptobase.FeToBytes(p, montX)
	copy(pk[:], p[:])
	return pk
}

const charset = "abcdefghijklmnopqrstuvwxyz0123456789"

func randomSessionID() string {
	b := make([]byte, 8)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func calculateK(R *cryptobase.ExtendedGroupElement, A *cryptobase.ExtendedGroupElement, data []byte) ([32]byte, error) {
	var edPublicKey = new([crypto.PublicKeySize]byte)
	A.ToBytes(edPublicKey)

	var encodedR [32]byte
	R.ToBytes(&encodedR)

	// calc k
	var k [32]byte
	var kHash [64]byte
	h := sha512.New()
	if _, err := h.Write(encodedR[:]); err != nil {
		return k, err
	}
	if _, err := h.Write(edPublicKey[:]); err != nil {
		return k, err
	}
	if _, err := h.Write(data); err != nil {
		return k, err
	}
	h.Sum(kHash[:0])
	cryptobase.ScReduce(&k, &kHash)

	return k, nil
}
