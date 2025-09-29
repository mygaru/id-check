package main

import (
	"flag"
	"fmt"
	"github.com/mygaru/id-check/pkg/mtls"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
	"testing"
	"time"
)

// keyFile must contain UNENCRYPTED key
func setFlags(caCrt, certFile, keyFile string) {
	//pwd, _ := os.Getwd()
	dir := "../../certs/"

	// yell @ madalv to give you test certificates
	flag.Set("mtlsCaCertPath", dir+caCrt)
	flag.Set("mtlsClientCertPath", dir+certFile)
	flag.Set("mtlsClientPrivateKeyPath", dir+keyFile)
	flag.Set("logLevel", "DEBUG")
}

func TestMtls_Revoked(t *testing.T) {
	setFlags("ca-chain.crt", "DV2.crt", "DV2_unenc.key")
	client, err := mtls.NewClient("Server1")
	assert.Nil(t, err)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI("https://localhost:9443/test")

	// Must fail because DV2 is revoked
	err = client.DoTimeout(req, resp, 5*time.Second)
	assert.NotNil(t, err)
}

func TestMtls(t *testing.T) {
	setFlags("ca-chain.crt", "DV1.crt", "DV1_unenc.key")
	client, err := mtls.NewClient("Server1")
	assert.Nil(t, err)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI("https://localhost:9443/test")

	err = client.DoTimeout(req, resp, 5*time.Second)
	assert.Nil(t, err)

	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
	assert.Equal(t, "Hello World!", string(resp.Body()))
}

func TestMtlsForward(t *testing.T) {
	setFlags("ca-chain.crt", "DV1.crt", "DV1_unenc.key")
	client, err := mtls.NewClient("Server1")
	assert.Nil(t, err)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI("https://localhost:9443/ccc")

	err = client.DoTimeout(req, resp, 5*time.Second)
	assert.Nil(t, err)
	fmt.Println(resp)

	assert.Equal(t, fasthttp.StatusOK, resp.StatusCode())
}

func TestMtls_Random(t *testing.T) {
	setFlags("example-ca.crt", "example_cl1.crt", "example_client1.key")
	client, err := mtls.NewClient("Server1")
	assert.Nil(t, err)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.Header.SetMethod(fasthttp.MethodGet)
	req.SetRequestURI("https://localhost:9443/test")

	// Must fail because example_cl1 is signed by other random CA
	err = client.DoTimeout(req, resp, 5*time.Second)
	assert.NotNil(t, err)
}

func TestMtls_GetCommonName(t *testing.T) {
	setFlags("ca-chain.crt", "DV1.crt", "DV1_unenc.key")

	cn, err := mtls.GetClientCertCN()
	assert.Nil(t, err)
	assert.Equal(t, "DV1", cn)
}
