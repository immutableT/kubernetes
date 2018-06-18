package envelope

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/api/core/v1"
	"crypto/rsa"
	"encoding/pem"
	"crypto/x509"
)

// Faking the whole KMS thing
const pk = `-----BEGIN PRIVATE KEY-----
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


var (
	scheme = runtime.NewScheme()
)



type CMSTransformer struct {
	serializer *protobuf.Serializer
}

func NewCMSTransformer() *CMSTransformer {
	install.Install(scheme)
	return &CMSTransformer{
		serializer: protobuf.NewSerializer(scheme, scheme, "application/protobuf"),
	}
}

func (e *CMSTransformer) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	out, err := e.transform(data, []byte("decrypted"))
	return out, false, err
}

func (e *CMSTransformer) TransformToStorage(data []byte, context value.Context) ([]byte, error) {

	// TODO Check if payload is CMS encoded - if yes pass it through
	// TODO If the payload is not CMS encoded - construct CMS envelope

	// For now simply passing through.
	return data, nil
}

func (e *CMSTransformer) transform(data, value []byte) ([]byte, error) {
	r, err := runtime.Decode(e.serializer, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %v", err)
	}

	s := r.(*v1.Secret)
	for k, v := range s.Data {
		// glog.Infof("Before: key[%s] value[%s]", k, v)
		data, err := OpenCMSEnvelop(v)
		if err != nil {
			return nil, err
		}

		s.Data[k] = data
		// glog.Infof("After: key[%s] value[%s]", k, s.Data[k])
	}

	s.APIVersion = "v1"
	s.Kind = "Secret"

	out, err := runtime.Encode(e.serializer, s)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %v", err)
	}

	return out, nil
}

func OpenCMSEnvelop(rawEnvelop []byte)  ([]byte, error){
	cmsEnvelope, err := ParseEnvelope(rawEnvelop)
	if err != nil {
		return nil, err
	}

	pk, err := parsePk()
	if err != nil {
		return nil, err
	}

	data, err := cmsEnvelope.DecryptData(pk)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func parsePk() (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pk))
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key.(*rsa.PrivateKey), nil
}


var _ value.Transformer = &CMSTransformer{}
