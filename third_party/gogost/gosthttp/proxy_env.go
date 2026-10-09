package gosthttp

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"sync"

	"golang.org/x/net/http/httpproxy"
)

var (
	environmentProxyOnce sync.Once
	environmentProxyFunc func(*url.URL) (*url.URL, error)
)

// ProxyFromEnvironment returns the proxy URL selected by HTTP_PROXY,
// HTTPS_PROXY and NO_PROXY. When the scheme-specific variable is empty,
// ALL_PROXY is used as a fallback. Uppercase variables take precedence over
// their lowercase equivalents, matching net/http.
func ProxyFromEnvironment(request *http.Request) (*url.URL, error) {
	if request == nil || request.URL == nil {
		return nil, errors.New("gosthttp: nil request passed to ProxyFromEnvironment")
	}
	environmentProxyOnce.Do(func() {
		config := httpproxy.FromEnvironment()
		hasHTTPProxy := config.HTTPProxy != ""
		allProxy := firstEnvironmentValue("ALL_PROXY", "all_proxy")
		if config.HTTPProxy == "" {
			config.HTTPProxy = allProxy
		}
		if config.HTTPSProxy == "" {
			config.HTTPSProxy = allProxy
		}
		// The CGI HTTPoxy protection applies specifically to HTTP_PROXY. An
		// ALL_PROXY fallback cannot be populated from an HTTP request header.
		if !hasHTTPProxy {
			config.CGI = false
		}
		environmentProxyFunc = config.ProxyFunc()
	})
	// httpproxy always bypasses exactly "localhost" and loopback IPs. Handle
	// that allocation-free common case before canonicalAddr builds a new
	// host:port string and walks the matcher lists.
	host := request.URL.Hostname()
	if host == "localhost" {
		return nil, nil
	}
	if address, err := netip.ParseAddr(host); err == nil && address.IsLoopback() {
		return nil, nil
	}
	return environmentProxyFunc(request.URL)
}

func firstEnvironmentValue(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}
