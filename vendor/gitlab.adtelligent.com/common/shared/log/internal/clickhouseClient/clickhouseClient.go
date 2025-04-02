// This is a stripped down version of lib/clickhouseBatcher/internal/clickhouseClient
// that doesn't use lib/* packages in order to prevent log recursion.

package clickhouseClient

import (
	"fmt"
	"net"
	"time"

	"github.com/valyala/fasthttp"
)

type Client struct {
	c          *fasthttp.HostClient
	requestURI []byte
}

func New(addr string) *Client {
	c := &Client{
		requestURI: []byte("/"),
		c: &fasthttp.HostClient{
			Addr: addr,
			Dial: func(addr string) (net.Conn, error) {
				return fasthttp.DialTimeout(addr, 3*time.Second)
			},
			ReadTimeout:     10 * time.Second,
			WriteTimeout:    10 * time.Second,
			WriteBufferSize: 64 * 1024,
		},
	}
	return c
}

func (c *Client) BatchInsertCompressed(data []byte) error {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	req.Header.Set("Content-Type", "text/plain")
	req.Header.SetMethod("POST")
	req.Header.SetHost("clickhouse")
	req.Header.Set("Content-Encoding", "gzip")
	req.SetRequestURIBytes(c.requestURI)
	req.SetBody(data)

	err := c.c.Do(req, resp)
	if err == nil && resp.StatusCode() != fasthttp.StatusOK {
		err = fmt.Errorf("Non-200 response: %q", resp)
	}
	fasthttp.ReleaseRequest(req)
	fasthttp.ReleaseResponse(resp)
	return err
}

// SetAuth sets auth params for the client.
//
// The method must be called before calling other Client methods.
func (c *Client) SetAuth(user, password string) {
	var uri fasthttp.URI
	qa := uri.QueryArgs()
	qa.Set("user", user)
	qa.Set("password", password)
	c.requestURI = uri.RequestURI()
}
