package gosthttp

import (
	"context"
	"net/http"

	"gitverse.ru/uzer_007/gogost/v3/gosttls"
)

type connectionStateKey struct{}

type connectionStateProvider interface {
	GOSTConnectionState() gosttls.ConnectionState
}

func contextWithConnectionState(ctx context.Context, value any) context.Context {
	return context.WithValue(ctx, connectionStateKey{}, value)
}

// ConnectionState returns the GOST TLS state associated with a server request
// or with response.Request on the client side.
func ConnectionState(request *http.Request) (gosttls.ConnectionState, bool) {
	if request == nil {
		return gosttls.ConnectionState{}, false
	}
	switch value := request.Context().Value(connectionStateKey{}).(type) {
	case gosttls.ConnectionState:
		return value, true
	case *gosttls.ConnectionState:
		if value != nil {
			return *value, true
		}
	case connectionStateProvider:
		return value.GOSTConnectionState(), true
	case *gosttls.Conn:
		return value.ConnectionState(), true
	}
	return gosttls.ConnectionState{}, false
}

// ResponseConnectionState returns the GOST TLS state used for response.
func ResponseConnectionState(response *http.Response) (gosttls.ConnectionState, bool) {
	if response == nil {
		return gosttls.ConnectionState{}, false
	}
	return ConnectionState(response.Request)
}
