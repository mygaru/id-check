package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/http/httpproxy"
	"net"
	"net/url"
	"time"
)

type ProxyContext struct {
	BaseURLScheme   string
	ProxyURL        *url.URL
	ProxyAuthHeader string
}

// NewProxyContext resolves proxy for the provided base URI and precomputes auth header.
func NewProxyContext(baseURI string) (*ProxyContext, error) {
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return nil, fmt.Errorf("parse base uri %q: %w", baseURI, err)
	}

	proxyFunc := httpproxy.FromEnvironment().ProxyFunc()

	proxyURL, err := proxyFunc(&url.URL{Scheme: parsed.Scheme, Host: parsed.Host})
	if err != nil {
		return nil, fmt.Errorf("proxy lookup failed for %s: %w", parsed.String(), err)
	}

	pc := &ProxyContext{BaseURLScheme: parsed.Scheme, ProxyURL: proxyURL}

	if proxyURL != nil && proxyURL.User != nil {
		pc.ProxyAuthHeader = buildBasicProxyAuthHeader(proxyURL)
	}

	return pc, nil
}

func GetClient(req *fasthttp.Request, baseUrl string, enableProxy bool) (*fasthttp.Client, error) {
	if !enableProxy || httpproxy.FromEnvironment().HTTPSProxy == "" && httpproxy.FromEnvironment().HTTPProxy == "" {
		return &fasthttp.Client{}, nil
	}

	pc, err := NewProxyContext(baseUrl)
	if err != nil {
		return nil, err
	}

	// For plain HTTP (the caller's request will be sent to proxy as it is)
	if pc.BaseURLScheme == "http" && pc.ProxyURL != nil && pc.ProxyAuthHeader != "" {
		req.Header.Set("Proxy-Authorization", pc.ProxyAuthHeader)
	}

	return &fasthttp.Client{
		Dial: ProxyDialer(pc),
	}, nil
}

func ProxyDialer(pc *ProxyContext) fasthttp.DialFunc {
	return ProxyDialerTimeout(pc, 0)
}

func ProxyDialerTimeout(pc *ProxyContext, timeout time.Duration) fasthttp.DialFunc {
	return func(addr string) (net.Conn, error) {
		if pc == nil || pc.ProxyURL == nil {
			if timeout == 0 {
				return fasthttp.Dial(addr)
			}

			return fasthttp.DialTimeout(addr, timeout)
		}

		proxyHost := pc.ProxyURL.Host

		dialer := &net.Dialer{}

		if timeout > 0 {
			dialer.Timeout = timeout
		}

		conn, err := dialer.Dial("tcp", proxyHost)
		if err != nil {
			return nil, err
		}

		if pc.ProxyURL.Scheme == "https" {
			tlsCfg := &tls.Config{
				ServerName: pc.ProxyURL.Hostname(),
			}

			tlsConn := tls.Client(conn, tlsCfg)
			if err := tlsConn.Handshake(); err != nil {
				_ = tlsConn.Close()
				return nil, fmt.Errorf("TLS handshake with proxy failed: %w", err)
			}

			conn = tlsConn
		}

		isHTTPS := pc.BaseURLScheme == "https"

		if isHTTPS {
			req := "CONNECT " + addr + " HTTP/1.1\r\n"

			if pc.ProxyAuthHeader != "" {
				req += "Proxy-Authorization: " + pc.ProxyAuthHeader + "\r\n"
			}

			req += "\r\n"

			if _, err := conn.Write([]byte(req)); err != nil {
				_ = conn.Close()
				return nil, err
			}

			res := fasthttp.AcquireResponse()
			defer fasthttp.ReleaseResponse(res)

			res.SkipBody = true

			if err := res.Read(bufio.NewReader(conn)); err != nil {
				_ = conn.Close()
				return nil, fmt.Errorf("read from proxy failed: %w", err)
			}

			if res.Header.StatusCode() != 200 {
				_ = conn.Close()
				return nil, fmt.Errorf("could not connect to proxy: code: %d body %s", res.StatusCode(), string(res.Body()))
			}
		}

		return conn, nil
	}
}

func buildBasicProxyAuthHeader(proxyURL *url.URL) string {
	if proxyURL == nil || proxyURL.User == nil {
		return ""
	}

	u := proxyURL.User.Username()
	p, _ := proxyURL.User.Password()
	token := base64.StdEncoding.EncodeToString([]byte(u + ":" + p))

	return "Basic " + token
}
