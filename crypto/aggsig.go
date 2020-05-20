package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"

	"github.com/dvshur/distributed-signature/crypto/internal"

	"github.com/wavesplatform/gowaves/pkg/crypto"
)

func randomKey() ([crypto.SecretKeySize]byte, error) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		var sk crypto.SecretKey
		return sk, err
	}

	return crypto.GenerateSecretKey(seed[:]), nil
}

// CalcR, returns ri, Ri, error
func CalcR(sk *[32]byte, data []byte) (internal.ExtendedGroupElement, [32]byte, error) {
	var R internal.ExtendedGroupElement
	var r [32]byte

	var prefix = bytes.Repeat([]byte{0xff}, 32)
	prefix[0] = 0xfe

	random := make([]byte, 64)
	_, err := rand.Read(random)
	if err != nil {
		return R, r, err
	}

	var rHash [64]byte
	h := sha512.New()
	if _, err := h.Write(prefix); err != nil {
		return R, r, err
	}
	if _, err := h.Write(sk[:]); err != nil {
		return R, r, err
	}
	if _, err := h.Write(data); err != nil {
		return R, r, err
	}
	if _, err := h.Write(random[:]); err != nil {
		return R, r, err
	}
	h.Sum(rHash[:0])

	internal.ScReduce(&r, &rHash)
	internal.GeScalarMultBase(&R, &r)

	return R, r, nil
}

// CalcK ..
func CalcK(R, A *internal.ExtendedGroupElement, data []byte) ([32]byte, error) {
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
func CalcS(k, si, ri *[32]byte) *internal.FieldElement {
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

	sk1, _ := randomKey()
	// sk2, _ := RandomKey()

	// calculate A, ed25519 pub key
	var /* A1 A2,*/ A internal.ExtendedGroupElement
	// internal.GeScalarMultBase(&A1, &sk2)
	// internal.GeScalarMultBase(&A2, &sk2)
	internal.GeScalarMultBase(&A, &sk1)
	// internal.GeAdd(&A, &A1, &A2)

	// generate Ri, ri
	R1, r1, _ := CalcR(&sk1, message)
	// rr2, _ := CalcRR(&sk2, message)

	var R internal.ExtendedGroupElement
	R = R1
	// internal.GeAdd(&R, &R1, &R2)

	k, _ := CalcK(&R, &A, message)

	S1 := CalcS(&k, &sk1, &r1)
	// S2 := CalcS(&k, &sk2, &rr2.RSecret)

	signatureEd := CreateSig(&R, S1)

	// for verification
	var publicKeyEd = new([crypto.PublicKeySize]byte)
	A.ToBytes(publicKeyEd)

	signBit := publicKeyEd[31] & 0x80

	// transform sig?
	var signatureCurve [64]byte
	copy(signatureCurve[:], signatureEd[:])
	signatureCurve[63] &= 0x7f
	signatureCurve[63] |= signBit

	publicKeyCurve := CurvePKFromEdPK(&A)

	// signatureValid := crypto.Verify(pk, sigValid, message)

	signatureValid := crypto.Verify(publicKeyCurve, signatureCurve, message)

	if signatureValid {
		println("Cool, verified")
	} else {
		println("Failed")
	}
}
