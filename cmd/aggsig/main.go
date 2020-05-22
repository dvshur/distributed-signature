package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha512"

	"github.com/dvshur/distributed-signature/pkg/crypto"
	"github.com/dvshur/distributed-signature/pkg/cryptobase"
)

func randomSecretKey() ([crypto.SecretKeySize]byte, error) {
	seed := make([]byte, 32)
	_, err := rand.Read(seed)
	if err != nil {
		var sk crypto.SecretKey
		return sk, err
	}

	return crypto.GenerateSecretKey(seed[:]), nil
}

// CalcR returns Ri, ri
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

// CalcK returns k
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

// CalcS returns Si
func CalcS(k, si, ri *[32]byte) *cryptobase.FieldElement {
	var s [32]byte
	cryptobase.ScMulAdd(&s, k, si, ri)

	var S cryptobase.FieldElement
	cryptobase.FeFromBytes(&S, &s)

	return &S
}

// SumFE returns a sum of provided FieldElements
func SumFE(elements ...*cryptobase.FieldElement) cryptobase.FieldElement {
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

// CurveSigFromEd creates a Curve25519 signature from A, R and S
func CurveSigFromEd(A, R *cryptobase.ExtendedGroupElement, S *cryptobase.FieldElement) crypto.Signature {
	var AByte, RByte, SByte [32]byte
	A.ToBytes(&AByte)
	R.ToBytes(&RByte)
	cryptobase.FeToBytes(&SByte, S)

	// this gets us an ed25519 sig, R || S
	var signature [64]byte
	copy(signature[:], RByte[:])
	copy(signature[32:], SByte[:])

	// this transforms an ed25519 to a Curve25519 sig
	signBit := AByte[31] & 0x80
	signature[63] &= 0x7f
	signature[63] |= signBit

	return signature
}

// CurvePKFromEdPK transforms an ed25519 public key, A, to a Curve25519 public key
func CurvePKFromEdPK(A *cryptobase.ExtendedGroupElement) crypto.PublicKey {
	var pk crypto.PublicKey
	var edYPlusOne = new(cryptobase.FieldElement)
	cryptobase.FeAdd(edYPlusOne, &A.Y, &A.Z)
	var oneMinusEdY = new(cryptobase.FieldElement)
	cryptobase.FeSub(oneMinusEdY, &A.Z, &A.Y)
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

	sk1, _ := randomSecretKey()
	sk2, _ := randomSecretKey()

	// calculate A, ed25519 pub key
	var A1, A2, A cryptobase.ExtendedGroupElement
	cryptobase.GeScalarMultBase(&A1, &sk1)
	cryptobase.GeScalarMultBase(&A2, &sk2)
	cryptobase.GeAdd(&A, &A1, &A2)

	// generate Ri, ri
	R1, r1, _ := CalcR(&sk1, message)
	R2, r2, _ := CalcR(&sk2, message)

	// sum Ri to get R
	var R cryptobase.ExtendedGroupElement
	cryptobase.GeAdd(&R, &R1, &R2)

	k, _ := CalcK(&R, &A, message)

	S1 := CalcS(&k, &sk1, &r1)
	S2 := CalcS(&k, &sk2, &r2)

	S := SumFE(S1, S2)

	signatureCurve := CurveSigFromEd(&A, &R, &S)
	publicKeyCurve := CurvePKFromEdPK(&A)

	if crypto.Verify(publicKeyCurve, signatureCurve, message) {
		println("Success")
	} else {
		println("Fail")
	}
}
