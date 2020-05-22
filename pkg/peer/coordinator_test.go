package peer

import (
	"crypto/rand"
	"testing"

	"github.com/dvshur/distributed-signature/pkg/cryptobase"
)

func randomGE() cryptobase.ExtendedGroupElement {
	r := make([]byte, 32)
	rand.Read(r)
	var r2 [32]byte
	copy(r2[:], r[:32])
	var R cryptobase.ExtendedGroupElement
	R.FromBytes(&r2)
	return R
}

// Coordinator ..
func TestSumGeSlice(t *testing.T) {
	var actualR cryptobase.ExtendedGroupElement

	// empty slice
	var empty cryptobase.ExtendedGroupElement
	actualR = sumGe([]cryptobase.ExtendedGroupElement{})
	if actualR != empty {
		t.Errorf("Empty slice does not produce empty result. Got: %d.", actualR)
	}

	// slice size 1
	R1 := randomGE()
	actualR = sumGe([]cryptobase.ExtendedGroupElement{R1})
	if actualR != R1 {
		t.Errorf("Slice size 1 incorrect result, got: %d, want: %d", actualR, R1)
	}

	// slice size 2
	var expectedR, R2 cryptobase.ExtendedGroupElement
	R2 = randomGE()
	cryptobase.GeAdd(&expectedR, &R1, &R2)

	actualR = sumGe([]cryptobase.ExtendedGroupElement{R1, R2})

	if expectedR != actualR {
		t.Errorf("Sum was incorrect, got: %d, want: %d.", expectedR, actualR)
	}

	// same Ri, but inverted order — test commutativity
	invertedR := sumGe([]cryptobase.ExtendedGroupElement{R2, R1})
	if actualR != invertedR {
		t.Errorf("Sum is not commutative, R12: %d, R21: %d.", actualR, invertedR)
	}
}
