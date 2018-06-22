// Package protocol implements low level CMS types, parsing and generation.
package cms

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
)


var (
	// https://tools.ietf.org/html/rfc5652
	oidData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}

	// https://www.ietf.org/rfc/rfc3565.txt
	oidEncryptionAlgorithmAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidRSAEncryption                = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
)

// Envelope implementation of CMS ContentInfo.
// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
//
// ContentType ::= OBJECT IDENTIFIER
type Envelope struct {
	ContentType asn1.ObjectIdentifier
	Content     EnvelopedData `asn1:"explicit,tag:0"`
}

func ParseEnvelope(der []byte) (Envelope, error) {
	var e Envelope
	var rest []byte
	var err error

	if rest, err = asn1.Unmarshal(der, &e); err != nil {
		return e, err
	}
	if len(rest) > 0 {
		err = fmt.Errorf("unexpected trailing data")
	}

	return e, nil
}

func (e *Envelope) marshal() ([]byte, error) {
	return asn1.Marshal(*e)
}

//EnvelopedData ::= SEQUENCE {
//version CMSVersion,
//originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//recipientInfos RecipientInfos,
//encryptedContentInfo EncryptedContentInfo,
//unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EnvelopedData struct {
	Version              int
	OriginatorInfo       OriginatorInfo          `asn1:"optional,implicit,tag:0"`
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

// recipient retrieves recipient identified by a serial number of a certificate.
func (e *Envelope) recipient(certSerialNumber *big.Int) *KeyTransRecipientInfo {
	for _, r := range e.Content.RecipientInfos {
		if r.RecipientIdentifier.SerialNumber.Cmp(certSerialNumber) == 0 {
			return &r
		}
	}

	return nil
}

func (e *Envelope) dek(recipientCertSN *big.Int, kms *AsymmetricKMS) ([]byte, error) {
	r := e.recipient(recipientCertSN)
	if r == nil {
		return nil, fmt.Errorf("unable to find recipient identified by SN:%d", recipientCertSN)
	}

	dek, err := kms.Decrypt(r.EncryptedKey)
	if err != nil {
		return nil, err
	}

	return dek, nil
}

//IssuerAndSerialNumber ::= SEQUENCE {
//issuer Name,
//serialNumber CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

func newIssuerAndSerialNumber(cert *x509.Certificate) IssuerAndSerialNumber {
	return IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	}
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

func newKeyTransRecipientInfo(encryptedKey []byte, cert *x509.Certificate) (KeyTransRecipientInfo, error) {
	//marshaledKey, err := asn1.Marshal(encryptedKey)
	//if err != nil {
	//	return KeyTransRecipientInfo{}, err
	//}

	return KeyTransRecipientInfo{
		Version:                0,
		RecipientIdentifier:    newIssuerAndSerialNumber(cert),
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidRSAEncryption},
		EncryptedKey:           encryptedKey,
	}, nil
}

type decryptFunc func(key []byte, envelope *Envelope) (plainText []byte, err error)

func (e *Envelope) unWrap(recipientCertSN *big.Int, kms *AsymmetricKMS, decrypter decryptFunc) ([]byte, error) {
	dek, err := e.dek(recipientCertSN, kms)
	if err != nil {
		return nil, err
	}

	data, err := decrypter(dek, e)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func unMarshalBytes(in []byte) ([]byte, error) {
	var out []byte
	rest, err := asn1.Unmarshal(in, &out)
	if len(rest) > 0 {
		return nil, asn1.SyntaxError{Msg: "trailing data"}
	}
	if err != nil {
		return nil, err
	}

	return out, nil
}