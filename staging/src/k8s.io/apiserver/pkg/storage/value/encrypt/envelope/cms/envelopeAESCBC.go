package cms

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
)

const aesKeySizeInBytes = 32

type envelopeAESCBC struct {
	Envelope
	kms           *AsymmetricKMS
	iv            []byte
	encryptedDEK  []byte
	encryptedData []byte
}

func newEnvelopeAESCBC(data, dek, iv []byte, kms *AsymmetricKMS) (envelopeAESCBC, error) {
	result := envelopeAESCBC{}
	result.kms = kms
	data = pad(data)
	var err error

	if dek == nil {
		dek = make([]byte, aesKeySizeInBytes)
		_, err := rand.Read(dek)
		if err != nil {
			return envelopeAESCBC{}, fmt.Errorf("failed to generate DEK, %v", err)
		}
	}

	if iv == nil {
		iv = make([]byte, aes.BlockSize)
		_, err := rand.Read(iv)
		if err != nil {
			return envelopeAESCBC{}, fmt.Errorf("failed to generate IV, %v", err)
		}
	}
	result.iv = iv

	result.encryptedData, err = result.encrypt(dek, data)
	if err != nil {
		return envelopeAESCBC{}, fmt.Errorf("failed to encrypt data in AES CBC mode, %v", err)
	}

	result.encryptedDEK, err = kms.Encrypt(dek)
	if err != nil {
		return envelopeAESCBC{}, err
	}

	c, err := result.newEnvelopedData(kms.Certificate())
	if err != nil {
		return envelopeAESCBC{}, err
	}

	result.Envelope = Envelope{
		ContentType: oidEnvelopedData,
		Content:     c,
	}

	return result, nil
}

func (e *envelopeAESCBC) newEnvelopedData(cert *x509.Certificate) (EnvelopedData, error) {
	r, err := newKeyTransRecipientInfo(e.encryptedDEK, cert)
	if err != nil {
		return EnvelopedData{}, err
	}

	c, err := e.newEncryptedContentInfo(e.iv, e.encryptedData)
	if err != nil {
		return EnvelopedData{}, err
	}

	return EnvelopedData{
		Version:              0,
		RecipientInfos:       []KeyTransRecipientInfo{r},
		EncryptedContentInfo: c,
	}, nil
}

func (e *envelopeAESCBC) newEncryptedContentInfo(iv, data []byte) (EncryptedContentInfo, error) {
	marshaledData, err := asn1.Marshal(data)
	if err != nil {
		return EncryptedContentInfo{}, err
	}

	contentEncryptionAlg := pkix.AlgorithmIdentifier{
		Algorithm:  oidEncryptionAlgorithmAES256CBC,
		Parameters: asn1.RawValue{Tag: asn1.TagOctetString, Bytes: iv},
	}

	out := EncryptedContentInfo{
		ContentType:                oidData,
		ContentEncryptionAlgorithm: contentEncryptionAlg,
		EncryptedContent:           asn1.RawValue{Tag: 0, Class: asn1.ClassContextSpecific, Bytes: marshaledData, IsCompound: false},
	}

	return out, nil
}

func (e *envelopeAESCBC) encrypt(key, plainText []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	cbc := cipher.NewCBCEncrypter(block, e.iv)
	cipherText := make([]byte, len(plainText))
	cbc.CryptBlocks(cipherText, plainText)
	return cipherText, nil
}

func decryptAESCBC(key []byte, e *Envelope) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// unMarshaledData, err := unMarshalBytes(e.Content.EncryptedContentInfo.EncryptedContent.Bytes)
	if err != nil {
		return nil, err
	}

	data := make([]byte, len(e.Content.EncryptedContentInfo.EncryptedContent.Bytes))
	cbc := cipher.NewCBCDecrypter(block, e.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes)
	cbc.CryptBlocks(data, e.Content.EncryptedContentInfo.EncryptedContent.Bytes)

	unPadded, err := unPad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	return unPadded, nil
}

func pad(data []byte) []byte {
	padLen := aes.BlockSize - (len(data) % aes.BlockSize)
	if padLen == 0 {
		padLen = aes.BlockSize
	}
	pad := bytes.Repeat([]byte{byte(padLen)}, padLen)
	return append(data, pad...)
}

func unPad(data []byte, blockLen int) ([]byte, error) {
	if blockLen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blockLen)
	}
	if len(data)%blockLen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}


