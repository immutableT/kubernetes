package cms
//
//import (
//	"bytes"
//	"testing"
//)
//
//func TestMarshal(t *testing.T) {
//	e, err := newEnvelopeAESCBC([]byte("Hello CMS."), decryptedDEK, iv, kms)
//	if err != nil {
//		t.Fatalf("failed to construct Envelope, err: %v", err)
//	}
//
//	got, err := e.marshal()
//	if err != nil {
//		t.Fatalf("failed to marshal envelope, err: %v", err)
//	}
//
//	if !bytes.Equal(got, referenceEnvelope) {
//		byteDiff(t, got, referenceEnvelope)
//		t.Fatalf("got %v, want %v", got, referenceEnvelope)
//	}
//}
//
//func byteDiff(t *testing.T, bs1, bs2 []byte) {
//	// Ensure that we have two non-nil slices with the same length.
//	if (bs1 == nil) || (bs2 == nil) {
//		t.Fatalf("expected a byte slice but got nil")
//	}
//	if len(bs1) != len(bs2) {
//		t.Fatalf("mismatched lengths, %d != %d", len(bs1), len(bs2))
//	}
//
//	// Populate and return the difference between the two.
//	diff := make([]int16, len(bs1))
//	for i := range bs1 {
//		diff[i] = int16(bs1[i]) - int16(bs2[i])
//	}
//
//	t.Logf("%v", diff)
//}
