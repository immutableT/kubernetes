package cms

import (
	"crypto/rsa"
	"fmt"
	"crypto/rand"
	"encoding/pem"
	"crypto/x509"
)

// Faking KMS
const (
	pk = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDWsHmjoBG/hPQp
xbvKSaEHgE1j/wxK3NpM/7zWX/GXSpiq1jVO+4UXvYcEroOPTEg9uQ8NABCTcsBa
/hO59Ga2Rxur0GPByJTSJt61/bTTNGpkpB6HqPImoy4xeyU7XNczSf1dCDay9AJF
3HhZST8HpHedslb/RSlSTb5WrrmSxxbX1m5eTdUwuaUjYiUDRSjPovQ+ZAz5artM
2b7NFQqHtXksDX9L6H9rUb2zxi889xvQGaz1KI5uTtdXBHrsNFNZ4mS7IvxU2md2
ADF2PSCNAaAuUTWQ7cv0PQ7E52uViYZgeDvRzXRp5dy8wg+z1DPBrF6eZ2eKyB5s
HIzIHGp9AgMBAAECggEBAIDHuy97hSntBslH4y2knQNy4vlotGbzs78caJnvU2v9
Qza256NJHLzw41zbke8TQwJDT9PshgTsgJYUcqDJChOs89xMVIqZVyv4RP/GAAHx
HyDfkbCulxK2L69evyasuin56BE2LBmMZRCi/04Psc9TyKy/nY/iXLcSC2rTxF1W
FeQ2QeSsfxUUuEeHn/8jxze9dJ8GZTJGzoPKSAtOUUlnMX1VxxatmbXtH7nvABdC
KfW/vav56alywVLoxImIVL9fjsYrlz+xgIVIQ0+Bma9Pf332qacOoiuyrGfaSKq8
Xq/N7SzH8ulhTIl6q8oWWsO4aAfxV7uBgRqqqJamQgECgYEA8mf7Xu2blu1wy35d
TuCoHi63GUXPISaLwfq3uo6d+zllQvExtFmsxsxHpyrCIU45ZvPhSXPJV+5nwI4z
aKVEZLqJhqEndCP8I0hVdDj2ts/pirTw+PbyPJVHSypne3kUY4fgCZm+OrOVDsDV
/JjTELvelfXPQ9iYxCFanZWmYHUCgYEA4rqWJkqSi1rOpmgRL7JFD94NOHRKSspa
b7ffDFWokr7+dEyGHjgC7xc7it8w5VxwzgXwKUo0dRjhSc07MdUTXl7S/ifFySIe
woTsOFgFO64H1nRVqenyv3C+zVQ7EEYaAseiHTTmfQL5PqZVYOfvtINwWeZsYYCi
MclGPLUgIOkCgYEAsFPjDhJY81iUi/HHffD9WbcxiTi2iq63SstNim7jjDMb7a31
MfNpMtK17Gu1+vQj3TfZ0Mxg0Y2h+vd1fdF6BquKDlx7jof+iMu9HWWyURi8ESG9
h9xaKKeNzKdzzuUsZ5oW5eTn81teOfUbszqXjbybFQpRUlDkDwcUGz0YYWECgYBh
x+aJjQ+2WetViPwgfdmbBkDdYAnKR4rJM5tWTnrtDsHelkIhNjbNtk9PjQIhaMSd
laIFrKMC/T/r/D7TNvmrcWm9gpmiLLznVzwo8I0RN/TZYEKxjNvMBGvFUdZHJnSB
Tmd0ASSGNYoYotOff2e5ihYiL2X+huNsZUmNVPAOQQKBgD6A4gTL2Y3XPqRjlHsz
/+nNBafw0RNvEe0g9JNRv2XIjQbCNn6WVhgwQWjnOG5QKqe21EXUIxEhFkP3cwrD
tXrYQ+/4u2LpRFJA+/mf6mubYa38k4uihdP/u2tnoBh+PveWI9JLbIhm8G3WGYSb
vDB7L4Bhx8D/CLg7SBj1Kgi+
-----END PRIVATE KEY-----`

 c = `-----BEGIN CERTIFICATE-----
MIIDkjCCAnqgAwIBAgIJAMZndCSa9HbCMA0GCSqGSIb3DQEBCwUAMF4xCzAJBgNV
BAYTAlVTMQswCQYDVQQIDAJXQTEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UEAwwG
YWxleHRjMR8wHQYJKoZIhvcNAQkBFhBhbGV4dGNAZ21haWwuY29tMB4XDTE4MDYw
NzIyMjEwM1oXDTE4MDcwNzIyMjEwM1owXjELMAkGA1UEBhMCVVMxCzAJBgNVBAgM
AldBMRAwDgYDVQQHDAdTZWF0dGxlMQ8wDQYDVQQDDAZhbGV4dGMxHzAdBgkqhkiG
9w0BCQEWEGFsZXh0Y0BnbWFpbC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQDWsHmjoBG/hPQpxbvKSaEHgE1j/wxK3NpM/7zWX/GXSpiq1jVO+4UX
vYcEroOPTEg9uQ8NABCTcsBa/hO59Ga2Rxur0GPByJTSJt61/bTTNGpkpB6HqPIm
oy4xeyU7XNczSf1dCDay9AJF3HhZST8HpHedslb/RSlSTb5WrrmSxxbX1m5eTdUw
uaUjYiUDRSjPovQ+ZAz5artM2b7NFQqHtXksDX9L6H9rUb2zxi889xvQGaz1KI5u
TtdXBHrsNFNZ4mS7IvxU2md2ADF2PSCNAaAuUTWQ7cv0PQ7E52uViYZgeDvRzXRp
5dy8wg+z1DPBrF6eZ2eKyB5sHIzIHGp9AgMBAAGjUzBRMB0GA1UdDgQWBBQjwAVV
i8FIoJYcTlUXjptSmo+wfzAfBgNVHSMEGDAWgBQjwAVVi8FIoJYcTlUXjptSmo+w
fzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAIv/zBIsg6jFeJ
OQ8nsygoHeRW9fTB3b4HwKOdQkch6ImkZ8Vev7hK4VCm+JKbpI0WMPCpz5/J2Shn
2LiLJtaOAYksBCleC6hcJzB7tuRFve3WvbFsr1uyqZP3mB/cHLARmwweO3r4RhNG
QrkmJwBjHi6tDVVvPBVNsL6b4nIbecCCykB+Wre4qv8NrHYMHuMivHOmdyW8L04M
qkD1nKIkWXevf7SKvd7NHsr9N7WJXA0kkqN7ef4KrcS/FZHRvSrytwRuGpQwMYjc
27iiACKtux85qajsAF9NSzva9m2Od+GlQ4Xat9w4b3IPIo104syS00wNnheoyk4F
hhrtRHYS
-----END CERTIFICATE-----`
)

var cert = mustParseCert()

type AsymmetricKMS struct {
	pk *rsa.PrivateKey
	pb *rsa.PublicKey
}

func NewAsymmetricKMS() *AsymmetricKMS {
	return &AsymmetricKMS{mustParsePK(), mustParseCert().PublicKey.(*rsa.PublicKey)}
}

func (k *AsymmetricKMS) Certificate() *x509.Certificate {
	return mustParseCert()
}

func (k *AsymmetricKMS)Decrypt(cipher []byte) ([]byte, error) {
	rng := rand.Reader
	plaintext, err := rsa.DecryptPKCS1v15(rng, k.pk, cipher)
	if err != nil {
		return nil, fmt.Errorf("Error from decryption: %s\n", err)
	}
	return plaintext, nil
}

func (k *AsymmetricKMS) Encrypt(plain []byte) ([]byte, error) {
	c, err := rsa.EncryptPKCS1v15(rand.Reader, k.pb, plain)
	if err != nil {
		return nil, err
	}

	return c, nil
}


func mustParsePK() *rsa.PrivateKey {
	block, _ := pem.Decode([]byte(pk))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	return key.(*rsa.PrivateKey)
}

func mustParseCert() *x509.Certificate {
	block, _ := pem.Decode([]byte(c))
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("failed to parse certificate: " + err.Error())
	}

	return cert
}
