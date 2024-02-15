package mux

import (
	"net/http"

	"github.com/davron112/lura/v2/config"
	"github.com/davron112/lura/v2/router/mux"
	"github.com/unrolled/secure"

	httpsecure "github.com/davron112/krakend-httpsecure/v2"
)

// NewSecureMw creates a secured middleware for the mux engine
func NewSecureMw(cfg config.ExtraConfig) mux.HandlerMiddleware {
	opt, ok := httpsecure.ConfigGetter(cfg).(secure.Options)
	if !ok {
		return identityMiddleware{}
	}

	return secure.New(opt)
}

type identityMiddleware struct{}

func (i identityMiddleware) Handler(h http.Handler) http.Handler {
	return h
}
