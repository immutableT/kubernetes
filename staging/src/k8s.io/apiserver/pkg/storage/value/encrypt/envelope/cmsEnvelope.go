package envelope

import (
	"fmt"

	"github.com/golang/glog"

	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer/protobuf"
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/api/core/v1"
)

var (
	scheme = runtime.NewScheme()
)

type CMSEnvelope struct {
	serializer *protobuf.Serializer
}

func NewCMSEnvelope() *CMSEnvelope {
	install.Install(scheme)
	return &CMSEnvelope{
		serializer: protobuf.NewSerializer(scheme, scheme, "application/protobuf"),
	}
}

func (e *CMSEnvelope) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	out, err := e.transform(data, []byte("decrypted"))
	return out, false, err
}

func (e *CMSEnvelope) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	return e.transform(data, []byte("encrypted"))
}

func (e *CMSEnvelope) transform(data, value []byte) ([]byte, error) {
	r, err := runtime.Decode(e.serializer, data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %v", err)
	}

	s := r.(*v1.Secret)
	for k, v := range s.Data {
		glog.Infof("Before: key[%s] value[%s]", k, v)
		s.Data[k] = value
		glog.Infof("After: key[%s] value[%s]", k, s.Data[k])
	}

	s.APIVersion = "v1"
	s.Kind = "Secret"

	out, err := runtime.Encode(e.serializer, s)
	if err != nil {
		return nil, fmt.Errorf("failed to encode %v", err)
	}

	return out, nil
}




var _ value.Transformer = &CMSEnvelope{}
