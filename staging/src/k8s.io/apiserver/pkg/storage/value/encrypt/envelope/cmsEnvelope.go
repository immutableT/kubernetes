package envelope

import (
	"k8s.io/apiserver/pkg/storage/value"
	"k8s.io/kubernetes/pkg/apis/core"
	"k8s.io/kubernetes/pkg/apis/core/install"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"

	"github.com/golang/glog"
	"fmt"
)

var scheme = runtime.NewScheme()

type CMSEnvelope struct {
	decoder           runtime.Decoder
}

func NewCMSEnvelope() *CMSEnvelope {
	// Is this required - probably already done somewhere else?
	install.Install(scheme)
	return &CMSEnvelope{
		decoder: serializer.NewCodecFactory(scheme).UniversalDecoder(),
	}
}

func (e *CMSEnvelope) TransformFromStorage(data []byte, context value.Context) ([]byte, bool, error) {
	s, err := e.decode(data)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode: %v", err)
	}
	glog.Infof("Entered cmsEnvelop TransformFromStorage\n%s", s.Name)
	for k, v := range s.Data {
		glog.Infof("key[%s] value[%s]\n", k, v)
	}
	return data, false, nil
}

func (e *CMSEnvelope) TransformToStorage(data []byte, context value.Context) ([]byte, error) {
	s, err := e.decode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}
	glog.Infof("Entered cmsEnvelop TransformToStorage\n%s", s.Name)

	for k, v := range s.Data {
		glog.Infof("key[%s] value[%s]\n", k, v)
		s.Data[k] = []byte("encrypted")
	}

	// TODO Need to marshal s back to []byte
	return data, nil
}

func (e *CMSEnvelope) decode(raw []byte) (*core.Secret, error) {
	r, err := runtime.Decode(e.decoder, raw)
	if err != nil {
		return nil, fmt.Errorf("failed to decode: %v", err)
	}
	return r.(*core.Secret), nil
}

var _ value.Transformer = &CMSEnvelope{}