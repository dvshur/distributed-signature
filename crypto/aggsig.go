package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"

	"github.com/dvshur/distributed-signature/crypto/internal"

	"github.com/wavesplatform/gowaves/pkg/crypto"
)

// RandomKey ..
func RandomKey() ([crypto.SecretKeySize]byte, error) {
	var sk crypto.SecretKey

	sk1 := make([]byte, 32)
	_, err := rand.Read(sk1)
	if err != nil {
		return sk, err
	}

	copy(sk[:], sk1)
	return sk, nil
}

type RR struct {
	R       internal.ExtendedGroupElement
	RSecret [32]byte
}

// CalcRR, returns ri, Ri, error
func CalcRR(sk *[32]byte, data []byte) (*RR, error) {
	var R internal.ExtendedGroupElement

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
	if _, err := h.Write(sk[:]); err != nil {
		return nil, err
	}
	if _, err := h.Write(data); err != nil {
		return nil, err
	}
	if _, err := h.Write(random[:]); err != nil {
		return nil, err
	}
	h.Sum(rHash[:0])

	var r [32]byte
	internal.ScReduce(&r, &rHash)
	internal.GeScalarMultBase(&R, &r)

	return &RR{
		R:       R,
		RSecret: r,
	}, nil
}

// CalcK ..
func CalcK(R *internal.ExtendedGroupElement, A *internal.ExtendedGroupElement, data []byte) ([32]byte, error) {
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

// CalcS ..
func CalcS(k *[32]byte, si *[32]byte, ri *[32]byte) *internal.FieldElement {
	var s [32]byte
	internal.ScMulAdd(&s, k, si, ri)

	var S internal.FieldElement
	internal.FeFromBytes(&S, &s)

	return &S
}

// CreateSig ..
func CreateSig(R *internal.ExtendedGroupElement, Ss ...*internal.FieldElement) crypto.Signature {
	var signature [64]byte

	// calc S = S0 + ... + Sn
	var S internal.FieldElement
	for _, Si := range Ss {
		internal.FeAdd(&S, &S, Si)
	}

	// serialize sig to bytes
	var RByte, SByte [32]byte
	R.ToBytes(&RByte)
	internal.FeToBytes(&SByte, &S)

	copy(signature[:], RByte[:])
	copy(signature[32:], SByte[:])

	return signature
}

func CurvePKFromEdPK(ed *internal.ExtendedGroupElement) crypto.PublicKey {
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

func main() {
	message := make([]byte, 4)
	message = append(message, 1, 1, 1, 1)

	sk1, _ := RandomKey()
	// sk2, _ := RandomKey()

	// calculate A, ed25519 pub key
	var /* A1 A2,*/ A internal.ExtendedGroupElement
	// internal.GeScalarMultBase(&A1, &sk2)
	// internal.GeScalarMultBase(&A2, &sk2)
	internal.GeScalarMultBase(&A, &sk1)
	// internal.GeAdd(&A, &A1, &A2)

	// generate r_i
	rr1, _ := CalcRR(&sk1, message)
	// rr2, _ := CalcRR(&sk2, message)

	var R internal.ExtendedGroupElement
	R = rr1.R
	// internal.GeAdd(&R, &rr1.R, &rr2.R)

	k, _ := CalcK(&R, &A, message)

	S1 := CalcS(&k, &sk1, &rr1.RSecret)
	// S2 := CalcS(&k, &sk2, &rr2.RSecret)

	signatureEd := CreateSig(&R, S1)

	// for verification
	var publicKeyEd = new([crypto.PublicKeySize]byte)
	A.ToBytes(publicKeyEd)

	// signBit := publicKeyEd[31] & 0x80

	// // transform sig?
	var signatureCurve [64]byte
	copy(signatureCurve[:], signatureEd[:])
	// signatureCurve[63] &= 0x7f
	// signatureCurve[63] |= signBit

	// publicKeyCurve := CurvePKFromEdPK(&A)

	seed, _ := RandomKey()
	sk := crypto.GenerateSecretKey(seed[:])

	sk01 := [crypto.SecretKeySize]byte(sk)
	var A0 internal.ExtendedGroupElement
	internal.GeScalarMultBase(&A0, &sk01)
	pk := CurvePKFromEdPK(&A0)

	sigValid, _ := crypto.Sign(sk, message)

	signatureValid := crypto.Verify(pk, sigValid, message)

	// signatureValid := crypto.Verify(publicKeyCurve, signatureCurve, message)

	if signatureValid {
		println("Cool, verified")
	} else {
		println("Failed")
	}
}
