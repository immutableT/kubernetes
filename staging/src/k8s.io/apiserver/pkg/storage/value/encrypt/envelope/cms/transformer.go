package cms

import (
	"fmt"
	"math/big"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/kubernetes/pkg/apis/core/install"
)

var (
	scheme = runtime.NewScheme()
)

type Transformer struct {
	serializer       *protobuf.Serializer
	kms              *AsymmetricKMS
	certSerialNumber *big.Int
}

func NewTransformer(certSerialNumber *big.Int) *Transformer {
	install.Install(scheme)
	return &Transformer{
		serializer:       protobuf.NewSerializer(scheme, scheme, "application/protobuf"),
		kms:              NewAsymmetricKMS(),
		certSerialNumber: certSerialNumber,
	}
}

func (e *Transformer) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	r, err := runtime.Decode(e.serializer, data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode %v", err)
	}

	s := r.(*v1.Secret)
	for k, v := range s.Data {
		data, err := e.UnWrapEnvelop(v)
		if err != nil {
			return nil, false, err
		}

		s.Data[k] = data
	}

	s.APIVersion = "v1"
	s.Kind = "Secret"

	out, err := runtime.Encode(e.serializer, s)
	if err != nil {
		return nil, false, fmt.Errorf("failed to encode %v", err)
	}

	return out, false, nil
}

func (e *Transformer) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	r, err := runtime.Decode(e.serializer, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %v", err)
	}

	s := r.(*v1.Secret)
	for k, v := range s.Data {
		_, err := e.UnWrapEnvelop(v)
		if err == nil {
			continue // secret is already in CMS envelope - just pass it through
		} else {
			c, err := newEnvelopeAESCBC(v, nil, nil, e.kms)
			if err != nil {
				return nil, err
			}
			s.Data[k], err = c.marshal()
			if err != nil {
				return nil, err
			}
		}
	}

	s.APIVersion = "v1"
	s.Kind = "Secret"

	out, err := runtime.Encode(e.serializer, s)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %v", err)
	}

	return out, nil
}

func (e *Transformer) UnWrapEnvelop(rawEnvelop []byte) ([]byte, error) {
	cmsEnvelope, err := ParseEnvelope(rawEnvelop)
	if err != nil {
		return nil, err
	}

	plainText, err := cmsEnvelope.unWrap(e.certSerialNumber, e.kms, decryptAESCBC)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

var _ value.Transformer = &Transformer{}
