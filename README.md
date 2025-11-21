# ID CHECK

The goal of this component is to act as a proxy, performing MTLSA (Mutual TLS Authentication) for any request that comes to it, then forwarding the request along.

Any client addressing requests to ID Check must have a valid certificate signed by myGaru's Certificate Authority.