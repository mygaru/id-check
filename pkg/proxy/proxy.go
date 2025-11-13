package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"github.com/valyala/fasthttp"
	"golang.org/x/net/http/httpproxy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"net"
	"net/http"
	"net/url"
	"time"
)

var isProxyEnabled = flag.Bool("isProxyEnabled", false, "Whether proxy is enabled")

type ProxyContext struct {
	BaseURLScheme   string
	ProxyURL        *url.URL
	ProxyAuthHeader string
}

func GetIsProxyEnabledFlag() bool {
	return *isProxyEnabled
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

func NewProxyContextFromHostPort(hostport string, useTLS bool) (*ProxyContext, error) {
	scheme := "http"

	if useTLS {
		scheme = "https"
	}

	baseURI := scheme + "://" + hostport
	return NewProxyContext(baseURI)
}

func GetClient(req *fasthttp.Request, baseUrl string) (*fasthttp.Client, error) {
	if !*isProxyEnabled || (httpproxy.FromEnvironment().HTTPSProxy == "" && httpproxy.FromEnvironment().HTTPProxy == "") {
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

func GetConnGRPC(hostport string) (*grpc.ClientConn, error) {
	if !*isProxyEnabled || httpproxy.FromEnvironment().HTTPProxy == "" {
		conn, err := grpc.Dial(hostport, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, fmt.Errorf("could not connect grpc server: %v", err)
		}

		return conn, nil
	}

	pc, err := NewProxyContextFromHostPort(hostport, false)
	if err != nil {
		return nil, fmt.Errorf("could not create proxy context: %v", err)
	}

	dialer := ProxyDialerGRPC(pc, 10*time.Second)

	conn, err := grpc.DialContext(
		context.Background(),
		hostport,
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("could not connect grpc server: %v", err)
	}

	return conn, nil
}

// ProxyDialerGRPC returns a function suitable for grpc.WithContextDialer.
func ProxyDialerGRPC(pc *ProxyContext, timeout time.Duration) func(ctx context.Context, addr string) (net.Conn, error) {
	return func(ctx context.Context, addr string) (net.Conn, error) {
		if pc == nil || pc.ProxyURL == nil {
			if timeout == 0 {
				d := &net.Dialer{}
				return d.DialContext(ctx, "tcp", addr)
			}

			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "tcp", addr)
		}

		proxyHost := pc.ProxyURL.Host

		dialer := &net.Dialer{}

		if timeout > 0 {
			dialer.Timeout = timeout
		}

		conn, err := dialer.DialContext(ctx, "tcp", proxyHost)
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

		connectReq := "CONNECT " + addr + " HTTP/1.1\r\n"

		if pc.ProxyAuthHeader != "" {
			connectReq += "Proxy-Authorization: " + pc.ProxyAuthHeader + "\r\n"
		}

		connectReq += "\r\n"

		if _, err := conn.Write([]byte(connectReq)); err != nil {
			_ = conn.Close()
			return nil, err
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("reading CONNECT response: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			_ = conn.Close()
			return nil, fmt.Errorf("proxy CONNECT failed: %s", resp.Status)
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
