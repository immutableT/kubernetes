package cms

import (
	"bytes"
	"testing"
)

func TestUnMarshalCertificateSN(t *testing.T) {
	e, err := unmarshal(envelope)
	if err != nil {
		t.Fatalf("failed to deserialize, err: %v", err)
	}

	r := e.recipient(cert.SerialNumber)
	if r.RecipientIdentifier.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("got %v, wat %v", r.RecipientIdentifier.SerialNumber, cert.SerialNumber)
	}
}

func TestDataEncryptionAlg(t *testing.T) {
	e, err := unmarshal(envelope)
	if err != nil {
		t.Fatalf("failed to deserialize, err: %v", err)
	}

	if ! e.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm.Equal(oidEncryptionAlgorithmAES256CBC) {
		t.Fatalf("got %v, want %v", e.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Algorithm, oidEncryptionAlgorithmAES256CBC)
	}
}

func TestUnMarshalKeyEncryptionAlg(t *testing.T) {
	e, err := unmarshal(envelope)
	if err != nil {
		t.Fatalf("failed to deserialize, err: %v", err)
	}

	r := e.recipient(cert.SerialNumber)
	if ! oidRSAEncryption.Equal(r.KeyEncryptionAlgorithm.Algorithm) {
		t.Fatalf("got %v, wat %v", r.KeyEncryptionAlgorithm.Algorithm, oidRSAEncryption)
	}
}

//func TestUnMarshalDEK(t *testing.T) {
//	e, err := unmarshal(envelop)
//	if err != nil {
//		t.Fatalf("failed to deserialize, err: %v", err)
//	}
//
//	gotDEK, err := e.dek(cert.SerialNumber, kms)
//	if err != nil {
//		t.Fatalf("failed to get DEK, err: %v", err)
//	}
//
//	if !bytes.Equal(gotDEK, decryptedDEK) {
//		t.Fatalf("got %v, want %v", gotDEK, decryptedDEK)
//	}
//}

func TestUnMarshalEncryptedContent(t *testing.T) {
	want := encryptedContent
	e, err := unmarshal(envelope)
	if err != nil {
		t.Fatalf("failed to deserialize, err: %v", err)
	}

	got := e.Content.EncryptedContentInfo.EncryptedContent.Bytes
	if err != nil {
		t.Fatalf("failed to get data, err: %v", err)
	}

	if !bytes.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)

	}
}

func TestUnMarshalData(t *testing.T) {
	e, err := unmarshal(envelope)
	if err != nil {
		t.Fatalf("failed to deserialize, err: %v", err)
	}

	gotData, err := e.unWrap(cert.SerialNumber, kms, decryptAESCBC)
	if err != nil {
		t.Fatalf("failed to get data, err: %v", err)
	}

	if !bytes.Equal(gotData, data) {
		t.Fatalf("got %v, want %v", gotData, data)
	}
}

