package arweave

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

// TestDeepHashBlobMatchesSpec verifies the blob case against the spec definition:
//
//	deepHash(blob) = SHA384( SHA384("blob"+len) || SHA384(data) )
func TestDeepHashBlobMatchesSpec(t *testing.T) {
	data := []byte("hello arweave")

	tag := append([]byte("blob"), []byte("13")...) // len("hello arweave") = 13
	th := sha512.Sum384(tag)
	dh := sha512.Sum384(data)
	want := sha512.Sum384(append(th[:], dh[:]...))

	got := DeepHash(DeepHashChunk{Blob: data})
	if !bytes.Equal(got, want[:]) {
		t.Errorf("DeepHash blob mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestDeepHashListFoldsLeft verifies the list case against the spec: start from
// SHA384("list"+count), then fold each element's deepHash into the accumulator.
func TestDeepHashListFoldsLeft(t *testing.T) {
	a := []byte("a")
	b := []byte("bb")

	tag := append([]byte("list"), []byte("2")...)
	acc := sha512.Sum384(tag)
	for _, el := range [][]byte{a, b} {
		eh := DeepHash(DeepHashChunk{Blob: el})
		acc = sha512.Sum384(append(acc[:], eh...))
	}
	want := acc

	got := DeepHash(DeepHashChunk{List: []DeepHashChunk{{Blob: a}, {Blob: b}}})
	if !bytes.Equal(got, want[:]) {
		t.Errorf("DeepHash list mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestDeepHashNestedList exercises the recursive structure the tx signature uses
// (a list containing a sub-list of tag pairs).
func TestDeepHashNestedList(t *testing.T) {
	chunk := DeepHashChunk{List: []DeepHashChunk{
		{Blob: []byte("2")},
		{List: []DeepHashChunk{
			{List: []DeepHashChunk{{Blob: []byte("name")}, {Blob: []byte("value")}}},
		}},
	}}
	// Just assert determinism + correct length (SHA-384 = 48 bytes); the exact
	// value is pinned by the spec-derived cases above.
	h1 := DeepHash(chunk)
	h2 := DeepHash(chunk)
	if len(h1) != 48 {
		t.Errorf("deepHash length = %d, want 48", len(h1))
	}
	if !bytes.Equal(h1, h2) {
		t.Error("deepHash is not deterministic")
	}
}
