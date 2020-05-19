package aggsig

import (
	"crypto/sha512"
	"errors"
	"fmt"
	"math/rand"
	"sync"

	"distributed-sig/crypto/internal"

	"github.com/wavesplatform/gowaves/pkg/crypto"
)

// Coordinator ..
type Coordinator interface {
	Keygen(clientID string) (crypto.PublicKey, error)
	Sign(clientID string, message []byte) (crypto.Signature, error)
	GetPublicKey(clientID string) (crypto.PublicKey, bool)
}

// CoordinatorImpl ..
type CoordinatorImpl struct {
	peers     []Peer
	pubKeysEd map[string]internal.ExtendedGroupElement
	mux       sync.Mutex
}

// NewCoordinator ..
func NewCoordinator(peers []Peer) Coordinator {
	return &CoordinatorImpl{
		peers:     peers,
		pubKeysEd: make(map[string]internal.ExtendedGroupElement),
		mux:       sync.Mutex{},
	}
}

// GetPublicKey ..
func (c *CoordinatorImpl) GetPublicKey(clientID string) (crypto.PublicKey, bool) {
	A, ok := c.pubKeysEd[clientID]
	return curvePKFromEdPK(&A), ok
}

// Keygen ..
func (c *CoordinatorImpl) Keygen(clientID string) (crypto.PublicKey, error) {
	errors := make(chan error)
	AA := make(chan internal.ExtendedGroupElement)

	// get all peers Ai
	for _, p := range c.peers {
		go func() {
			Ai, err := p.Ai(clientID)
			if err != nil {
				errors <- err
				return
			}
			AA <- *Ai
		}()
	}

	var A internal.ExtendedGroupElement
	for range c.peers {
		select {
		case Ai := <-AA:
			internal.GeAdd(&A, &A, &Ai)
		case err := <-errors:
			var pk crypto.PublicKey
			return pk, err
		}
	}

	c.mux.Lock()
	c.pubKeysEd[clientID] = A
	c.mux.Unlock()

	return curvePKFromEdPK(&A), nil
}

// Sign ..
func (c *CoordinatorImpl) Sign(clientID string, message []byte) (crypto.Signature, error) {
	var signature crypto.Signature

	A, clientExists := c.pubKeysEd[clientID]
	if !clientExists {
		return signature, errors.New(fmt.Sprint("client id %s does not exist", clientID))
	}

	errors := make(chan error)
	sessionID := randomSessionID()

	// phase1: ask peers for R_i to calculate R
	var R internal.ExtendedGroupElement
	RR := make(chan internal.ExtendedGroupElement)
	for _, p := range c.peers {
		go func() {
			Ri, err := p.Ri(clientID, sessionID, message)
			if err != nil {
				errors <- err
				return
			}
			RR <- *Ri
		}()
	}
	for range c.peers {
		select {
		case Ri := <-RR:
			internal.GeAdd(&R, &R, &Ri)
		case err := <-errors:
			return signature, err
		}
	}

	k, err := calculateK(&R, &A, message)
	if err != nil {
		return signature, err
	}

	// phase 2: ask peers for S_i to calculate S
	var S internal.FieldElement
	SS := make(chan internal.FieldElement)
	for _, p := range c.peers {
		go func() {
			Si, err := p.Si(clientID, sessionID, k)
			if err != nil {
				errors <- err
				return
			}
			SS <- *Si
		}()
	}
	for range c.peers {
		select {
		case Si := <-SS:
			internal.FeAdd(&S, &S, &Si)
		case err := <-errors:
			return signature, err
		}
	}

	// serialize R, S to bytes
	var RByte, SByte [32]byte
	R.ToBytes(&RByte)
	internal.FeToBytes(&SByte, &S)
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

func curvePKFromEdPK(ed *internal.ExtendedGroupElement) crypto.PublicKey {
	var pk crypto.PublicKey
	var edYPlusOne = new(internal.FieldElement)
	internal.FeAdd(edYPlusOne, &ed.Y, &ed.Z)
	var oneMinusEdY = new(internal.FieldElement)
	internal.FeSub(oneMinusEdY, &ed.Z, &ed.Y)
	var invOneMinusEdY = new(internal.FieldElement)
	internal.FeInvert(invOneMinusEdY, oneMinusEdY)
	var montX = new(internal.FieldElement)
	internal.FeMul(montX, edYPlusOne, invOneMinusEdY)
	p := new([crypto.PublicKeySize]byte)
	internal.FeToBytes(p, montX)
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

func calculateK(R *internal.ExtendedGroupElement, A *internal.ExtendedGroupElement, data []byte) ([32]byte, error) {
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
	internal.ScReduce(&k, &kHash)

	return k, nil
}
