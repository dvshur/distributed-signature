package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"

	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/cryptobase"
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
func CalcR(sk *[32]byte, data []byte) (cryptobase.ExtendedGroupElement, [32]byte, error) {
	var R cryptobase.ExtendedGroupElement
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

	cryptobase.ScReduce(&r, &rHash)
	cryptobase.GeScalarMultBase(&R, &r)

	return R, r, nil
}

// CalcK ..
func CalcK(R, A *cryptobase.ExtendedGroupElement, data []byte) ([32]byte, error) {
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

// CalcS ..
func CalcS(k, si, ri *[32]byte) *cryptobase.FieldElement {
	var s [32]byte
	cryptobase.ScMulAdd(&s, k, si, ri)

	var S cryptobase.FieldElement
	cryptobase.FeFromBytes(&S, &s)

	return &S
}

// CreateSig ..
func CreateSig(R *cryptobase.ExtendedGroupElement, Ss ...*cryptobase.FieldElement) crypto.Signature {
	var signature [64]byte

	// calc S = S0 + ... + Sn
	var S cryptobase.FieldElement
	for _, Si := range Ss {
		cryptobase.FeAdd(&S, &S, Si)
	}

	// serialize sig to bytes
	var RByte, SByte [32]byte
	R.ToBytes(&RByte)
	cryptobase.FeToBytes(&SByte, &S)

	copy(signature[:], RByte[:])
	copy(signature[32:], SByte[:])

	return signature
}

func CurvePKFromEdPK(ed *cryptobase.ExtendedGroupElement) crypto.PublicKey {
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

func main() {
	message := make([]byte, 4)
	message = append(message, 1, 1, 1, 1)

	sk1, _ := randomKey()
	// sk2, _ := RandomKey()

	// calculate A, ed25519 pub key
	var /* A1 A2,*/ A cryptobase.ExtendedGroupElement
	// cryptobase.GeScalarMultBase(&A1, &sk2)
	// cryptobase.GeScalarMultBase(&A2, &sk2)
	cryptobase.GeScalarMultBase(&A, &sk1)
	// cryptobase.GeAdd(&A, &A1, &A2)

	// generate Ri, ri
	R1, r1, _ := CalcR(&sk1, message)
	// rr2, _ := CalcRR(&sk2, message)

	var R cryptobase.ExtendedGroupElement
	R = R1
	// cryptobase.GeAdd(&R, &R1, &R2)

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
