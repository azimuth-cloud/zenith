# zenith

Zenith is a reliable, scalable and secure tunnelling HTTP(S) proxy built using industry-standard
software and protocols.

Zenith consists of a server and a client which collaborate to establish a secure tunnel over which
traffic can then flow to the proxied service, even if that service is behind NAT and/or a firewall.

  * Expose services that are behind NAT or a firewall as subdomains of a parent domain.
    * Exposed services only need to be bound locally, i.e. to `localhost`, on an isolated Docker network
      or within the same Podman or Kubernetes pod as the Zenith client.
  * Perform TLS termination for proxied services.
  * Enforce external authentication and authorization for proxied services.
  * Uses industry-standard software and protocols:
    * [OpenSSH](https://en.wikipedia.org/wiki/OpenSSH) and
      [SSH port forwarding](https://help.ubuntu.com/community/SSH/OpenSSH/PortForwarding)
      to provide secure tunnels that bridge NAT or a firewall.
    * [Kubernetes](https://kubernetes.io/) for resilient and flexible services.
    * [Kubernetes Ingress resources](https://kubernetes.io/docs/concepts/services-networking/ingress/)
      and the
      [NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/)
      for performant, dynamic proxying.
    * [Hashicorp Consul](https://www.consul.io/) to glue everything together.
    * (Recommended) [cert-manager](https://cert-manager.io/docs/) for managing TLS certificates.

## Architecture

Zenith has two logical components, a server and a client, each of which has subcomponents. It also
leverages the power of Kubernetes to do most of the heavy lifting for the dynamic proxying.

The Zenith server consists of two main components, both of which are written in
[Python](https://www.python.org/) and deployed in Kubernetes:

  * A locked-down SSHD server that establishes secure tunnels with the Zenith clients and posts
    the resulting service information into Consul.
  * A sync component that receives updates from Consul and synchronises the corresponding
    `Service`, `Endpoint` and `Ingress` resources in Kubernetes.

The Zenith client is also written in [Python](https://www.python.org/), and it is responsible for
configuring and starting an SSH connection to the SSHD component of a Zenith server using the
[OpenSSH client](https://man.openbsd.org/ssh.1).

The architecture of Zenith is described in more detail in [Zenith Architecture](./docs/architecture.md).

## Deploying a Zenith server

The currently supported deployment mechanism for Zenith is to use [Helm](https://helm.sh/) to
deploy to a Kubernetes cluster. This documentation assumes that you already have a Kubernetes cluster
available for your Zenith deployment that has the
[NGINX Ingress Controller](https://kubernetes.github.io/ingress-nginx/) installed.

> **IMPORTANT**
>
> Before deploying Zenith, there must be a **wildcard DNS entry** pointing at the IP address
> of your Kubernetes Ingress Controller for Zenith to use - Zenith does **not** manage this.

For more detail on deploying and configuring a Zenith server, see
[Deploying and configuring a Zenith server](./docs/server.md).

## Proxying a service using the Zenith Client

The Zenith client establishes a secure tunnel with a Zenith server and ensures that traffic received
over that tunnel is forwarded to the proxied service.

### Container image

The Zenith client is made available on [GitHub Packages](https://github.com/features/packages)
as a multi-arch container image that is built for both AMD64 and ARM64:

```bash
docker run --rm ghcr.io/stackhpc/zenith-client:main zenith-client --help
```

### Python installation

The Zenith client can also be installed directly from GitHub using [pip](https://pip.pypa.io/en/stable/):

```bash
# configomatic is a dependency of the Zenith client
pip install git+https://github.com/stackhpc/configomatic.git
# Install the Zenith client
pip install git+https://github.com/stackhpc/zenith.git#subdirectory=client
# Show the Zenith client help
zenith-client --help
```

### Example

A service need only be bound locally in order to be proxied using Zenith - it only needs to
be reachable by the Zenith client.

In this example, we start an NGINX container on an isolated Docker network and proxy it by
deploying the Zenith client onto the same network:

```console
$ docker network create zenith-test
13124561fcf532b37c65a76a648964071c1dcb158d7cf4615c88ffd4e19c20f9

$ docker run --rm --detach --network zenith-test --name nginx nginx
d8a1f908ec0393b86885d71f4ad1c6f05704892ae2fbc8893368fa8067d2165d

$ docker run \
    --rm \
    --network zenith-test \
    ghcr.io/stackhpc/zenith-client:main \
    zenith-client \
      --server-address ${zenith_sshd_address} \
      --server-port ${zenith_sshd_port} \
      --forward-to-host nginx \
      --forward-to-port 80

[INFO] [CLIENT] Switching to uid '1001'
[INFO] [CLIENT] Generating temporary SSH private key
Generating public/private rsa key pair.
Your identification has been saved in /tmp/tmp0_nq34hb/id_rsa
Your public key has been saved in /tmp/tmp0_nq34hb/id_rsa.pub
The key fingerprint is:
SHA256:ZTyIk1S6v++aG87fsyoRT8cJY6gmw+XwwB6NoYyxjUw zenith-key
The key's randomart image is:
+---[RSA 2048]----+
|.E ..+....       |
|oB .*.o+.o+      |
|+.+o B=...=+ .   |
|    = =o.o..+    |
|     +. S+ .     |
|       .. .      |
|        o.       |
|       o.+ ..    |
|        BB=.oo   |
+----[SHA256]-----+
[INFO] [CLIENT] Spawning SSH process
[INFO] [CLIENT] Negotiating tunnel configuration
Warning: Permanently added '[REDACTED]' (ECDSA) to the list of known hosts.
[SERVER] [INFO] Waiting for configuration
eyJhbGxvY2F0ZWRfcG9ydCI6IDQyOTk1LCAic3ViZG9tYWluIjogImE4OWtoZDdramY0YmxvYXBk
Z2xoMW1qNXRqMnF0dGI5IiwgImJhY2tlbmRfcHJvdG9jb2wiOiAiaHR0cCJ9

END_CONFIGURATION
[INFO] [CLIENT] Tunnel configured successfully
[SERVER] [INFO] Received configuration: {
  "allocated_port": 42995,
  "subdomain": "a89khd7kjf4bloapdglh1mj5tj2qttb9",
  "backend_protocol": "http"
}
[SERVER] [INFO] Checking if Consul service already exists for allocated port
[SERVER] [INFO] No existing service found
[SERVER] [INFO] Registering service with Consul
[SERVER] [INFO] Registered service successfully
[SERVER] [INFO] Updating service health status in Consul
[SERVER] [INFO] Service health updated successfully
[SERVER] [INFO] Updating service health status in Consul
...
```

The client and server negotiate the tunnel configuration, and the final configuration that
is decided on is output on stdout, including the subdomain.

The NGINX test page will now be available at `http[s]://[subdomain].[zenith_base_domain]`.

For more detail on configuring the Zenith client, see [Configuring the Zenith client](./docs/client.md).
