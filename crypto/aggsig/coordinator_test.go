package aggsig

import (
	"distributed-sig/crypto/internal"
	"testing"
)

// Coordinator ..
func TestSumGeSlice(t *testing.T) {
	var actualR internal.ExtendedGroupElement

	// empty slice
	var empty internal.ExtendedGroupElement
	actualR = SumGeSlice([]internal.ExtendedGroupElement{})
	if actualR != empty {
		t.Errorf("Empty slice does not produce empty result. Got: %d.", actualR)
	}

	// slice size 1
	r1, _ := randomKey()
	var R1 internal.ExtendedGroupElement
	internal.GeScalarMultBase(&R1, &r1)
	actualR = SumGeSlice([]internal.ExtendedGroupElement{R1})
	if actualR != R1 {
		t.Errorf("Slice size 1 incorrect result, got: %d, want: %d", actualR, R1)
	}

	// slice size 2
	r2, _ := randomKey()
	var expectedR, R2 internal.ExtendedGroupElement
	internal.GeScalarMultBase(&R2, &r2)
	internal.GeAdd(&expectedR, &R1, &R2)

	actualR = SumGeSlice([]internal.ExtendedGroupElement{R1, R2})

	if expectedR != actualR {
		t.Errorf("Sum was incorrect, got: %d, want: %d.", expectedR, actualR)
	}

	// same Ri, but inverted order — test commutativity
	invertedR := SumGeSlice([]internal.ExtendedGroupElement{R2, R1})
	if actualR != invertedR {
		t.Errorf("Sum is not commutative, R12: %d, R21: %d.", actualR, invertedR)
	}
}
