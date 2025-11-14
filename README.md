# ID CHECK

ID Check is a lightweight reverse proxy that terminates mutual TLS connections, validates client certificates against myGaru's Certificate Authority (including CRL checks), and forwards trusted traffic to an upstream service.

Any client sending requests to ID Check must present a certificate issued by myGaru CA; the upstream request is decorated with the certificate’s `CommonName` so the origin service knows who called it.

## Listening Endpoint & Request Flow

- The server listens on the address provided by `mtlsServerListenAddr` (default `:443`) and accepts only TLS connections that successfully complete mutual authentication.
- Each request is re-created and forwarded to the URL configured via `idCheckForwardTrafficAddr`, preserving method, path, headers, body, and query string.
- ID Check injects the header `X-ClientID` with the caller’s certificate `CommonName`, allowing the upstream service to apply identity-aware logic.
- TLS handshakes trigger CRL fetches and signature checks on demand, ensuring revoked certificates are rejected before the request reaches the upstream service.
- A simple health/test path is exposed at `/test`, responding with `Hello World!` without forwarding upstream.

The certificate for the listening Endpoint (`mtlsClientCertPath`) need to be issued by well-known authority (e.g. Letsencrypt) to ensure connectivity from 3rd party sides without custom configuration on their side. Operator of the service is responsible for certificate lifecycle management (issuing, next renewals).

## Configuration

ID Check uses [`iniflags`](https://github.com/vharitonsky/iniflags); pass `--config=/path/to/config.ini` (or `-config`) when starting the binary or container. The sample file in `cfg/example.ini` illustrates the available settings:

```
[mtls / common]
mtlsCaCertPath =
mtlsCaCertURL = http://ca.mygaru.com/ca-chain
mtlsCrlCheckInterval = 1h

#[mtls / client]
#mtlsClientCertPath =
#mtlsClientPrivateKeyPath =

[mtls / server]
mtlsServerCertPath =
mtlsServerPrivateKeyPath =
mtlsServerListenAddr = :443
mtlsServerMaxBodySize = 536870912

[forwarding]
idCheckForwardTrafficAddr = http://id-hash.host-or-ip/pim
idCheckForwardTimeout = 10m

[proxy]
isProxyEnabled = false
```

- `mtls / common`: pick either a local CA bundle (`mtlsCaCertPath`) or a URL (`mtlsCaCertURL`); if both are set, the file path wins. This bundle is required to validate client certificates in incoming requests. The `mtlsCrlCheckInterval` instructs how often to refresh the CRL which comes in client ceriticates.
- `mtls / server`: specify server certificate/key used to terminate TLS, request body limits.
- `mtls / client`: optional client certificate/key for scenarios where ID Check itself must make mTLS calls (for example, when fetching upstream resources).
- `forwarding`: target origin base URL and timeout for outgoing calls.
- `proxy`: enable transparent proxying when outbound traffic must respect HTTP(S) proxy environment variables.

## Build & Deploy

### Docker-based

- Build the container image:
  ```
  docker build -t mygaru/id-check .
  ```
- Prepare a runtime configuration file (e.g. `/etc/id-check/base.ini`) with the correct parameters.
- Run the container, mounting certificates/configuration and publishing the chosen port (the Dockerfile defaults to exposing `8090`; ensure `mtlsServerListenAddr` matches the published port):
  ```
  docker run \
    -v /srv/id-check/base.ini:/etc/id-check/base.ini:ro \
    -v /srv/id-check/certs:/etc/id-check/certs:ro \
    -p 8443:8090 \
    mygaru/id-check \
    /usr/local/bin/id-check --config=/etc/id-check/base.ini
  ```
- Supply client/server certificates in the mounted directory, making sure the config points at the in-container paths.

### Systemd-based

1. Build and install the binary (using the vendored dependencies):
   ```
   make id-check
   install -D cmd/id-check/bin/id-check /usr/local/bin/id-check
   ```
2. Place your configuration at `/etc/id-check/base.ini` (or another location referenced via `--config`), including absolute paths to certificates readable by the service user.
3. Create a service unit such as:

```
[Unit]
Description=myGaru ID Check mTLS proxy
After=network.target

[Service]
User=root
Group=root
ExecStart=/usr/local/bin/id-check --config=/etc/id-check/base.ini
Restart=on-failure
RestartSec=5s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

4. Reload and start the service:
   ```
   systemctl daemon-reload
   systemctl enable --now id-check.service
   ```

## High availability
ID Check is the stateless, so no session stickiness required to make it working. To provide high availability, any technology by Operator's choice, which will ensure access to any available instance of the ID Check, can be used.
