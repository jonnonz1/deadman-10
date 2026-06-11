// Package arweave is a minimal, dependency-free Arweave client: just enough to
// sign and post a Format-2 transaction so a released vault can live on permanent
// storage. It deliberately avoids the goar SDK (which pulls in go-ethereum and
// gorm) to keep the security-critical binary small and auditable — only the Go
// standard library is used.
package arweave

import (
	"crypto/sha512"
	"strconv"
)

// DeepHashChunk is the recursive input to DeepHash: it is either a Blob or a
// List, mirroring Arweave's DeepHashChunk = Uint8Array | DeepHashChunk[]. IsList
// distinguishes the two even when List is empty (an empty tag list must still be
// hashed as "list0", not as a blob).
type DeepHashChunk struct {
	Blob   []byte
	List   []DeepHashChunk
	IsList bool
}

// listChunk builds a list-typed chunk (correct even for zero elements).
func listChunk(items []DeepHashChunk) DeepHashChunk {
	return DeepHashChunk{List: items, IsList: true}
}

// DeepHash implements Arweave's deep-hash over nested binary data using SHA-384,
// the message that a transaction signature is computed over.
//
//	blob: hash( hash("blob"+len) || hash(data) )
//	list: fold each element's deepHash into acc starting from hash("list"+count)
func DeepHash(chunk DeepHashChunk) []byte {
	if chunk.IsList || chunk.List != nil {
		tag := append([]byte("list"), []byte(strconv.Itoa(len(chunk.List)))...)
		return deepHashList(chunk.List, sha384(tag))
	}
	tag := append([]byte("blob"), []byte(strconv.Itoa(len(chunk.Blob)))...)
	tagHash := sha384(tag)
	dataHash := sha384(chunk.Blob)
	return sha384(concat(tagHash, dataHash))
}

// deepHashList left-folds each element's deep hash into the accumulator.
func deepHashList(list []DeepHashChunk, acc []byte) []byte {
	for _, el := range list {
		elHash := DeepHash(el)
		acc = sha384(concat(acc, elHash))
	}
	return acc
}

// sha384 returns the SHA-384 digest of b.
func sha384(b []byte) []byte {
	h := sha512.Sum384(b)
	return h[:]
}

// concat returns a||b as a fresh slice.
func concat(a, b []byte) []byte {
	out := make([]byte, 0, len(a)+len(b))
	out = append(out, a...)
	return append(out, b...)
}
