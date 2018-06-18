// Package protocol implements low level CMS types, parsing and generation.
package envelope

import (
	"crypto/x509/pkix"

	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"math/big"
)


// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER

type CMSEnvelope struct {
	ContentType asn1.ObjectIdentifier
	Content     EnvelopedData `asn1:"explicit,tag:0"`
}

//EnvelopedData ::= SEQUENCE {
//version CMSVersion,
//originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//recipientInfos RecipientInfos,
//encryptedContentInfo EncryptedContentInfo,
//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version              int
	OriginatorInfo       OriginatorInfo `asn1:"optional,implicit,tag:0"`
	RecipientInfos       []KeyTransRecipientInfo `asn1:"set"`
	EncryptedContentInfo EncryptedContentInfo
	UnProtectedAttrs     asn1.RawValue `asn1:"optional,implicit,tag:1"`
}

//OriginatorInfo ::= SEQUENCE {
//certs [0] IMPLICIT CertificateSet OPTIONAL,
//crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

type OriginatorInfo struct {
	Certificates []asn1.RawValue `asn1:"optional,implicit,set,tag:0"`
	CRLs         []asn1.RawValue `asn1:"optional,implicit,set,tag:1"`
}

//KeyTransRecipientInfo ::= SEQUENCE {
//version CMSVersion,  -- always set to 0 or 2
//rid RecipientIdentifier,
//keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//encryptedKey EncryptedKey }
type KeyTransRecipientInfo struct {
	Version                int
	RecipientIdentifier    IssuerAndSerialNumber
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

//IssuerAndSerialNumber ::= SEQUENCE {
//issuer Name,
//serialNumber CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

//EncryptedContentInfo ::= SEQUENCE {
//contentType ContentType,
//contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"optional,implicit,tag:0"`
}

func ParseEnvelope(der []byte) (e CMSEnvelope, err error) {
	var rest []byte
	if rest, err = asn1.Unmarshal(der, &e); err != nil {
		return
	}
	if len(rest) > 0 {
		err = errors.New("unexpected trailing data")
	}

	return
}

func (e *CMSEnvelope) unWrapDEK(pk *rsa.PrivateKey) ([]byte, error) {
	rng := rand.Reader
	plaintext, err := rsa.DecryptPKCS1v15(rng, pk, e.Content.RecipientInfos[0].EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("Error from decryption: %s\n", err)
	}
	return plaintext, nil
}

func (e *CMSEnvelope) DecryptData(pk *rsa.PrivateKey) ([]byte, error) {
	key, err := e.unWrapDEK(pk)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	iv := e.Content.EncryptedContentInfo.ContentEncryptionAlgorithm.Parameters.Bytes
	if len(iv) != block.BlockSize() {
		return nil, errors.New("CMS: encryption algorithm parameters are malformed")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	plaintext := make([]byte, len(e.Content.EncryptedContentInfo.EncryptedContent.Bytes))
	mode.CryptBlocks(plaintext, e.Content.EncryptedContentInfo.EncryptedContent.Bytes)

	return plaintext, nil
}

func ParseCert(pathToCert string) (*x509.Certificate, error) {
	certPEM, err := ioutil.ReadFile(pathToCert)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert, nil
}


func unpad(data []byte, blocklen int) ([]byte, error) {
	if blocklen < 1 {
		return nil, fmt.Errorf("invalid blocklen %d", blocklen)
	}
	if len(data)%blocklen != 0 || len(data) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(data))
	}

	// the last byte is the length of padding
	padlen := int(data[len(data)-1])

	// check padding integrity, all bytes should be the same
	pad := data[len(data)-padlen:]
	for _, padbyte := range pad {
		if padbyte != byte(padlen) {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padlen], nil
}
