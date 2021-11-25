# Configuring the Zenith client  <!-- omit in toc -->

The Zenith client establishes a secure tunnel with a Zenith server and ensures that traffic received
over that tunnel is forwarded to the proxied service.

## Contents  <!-- omit in toc -->

- [Installation](#installation)
  - [Container image](#container-image)
  - [Python installation](#python-installation)
- [Usage](#usage)
- [Specifying the Zenith SSHD server](#specifying-the-zenith-sshd-server)
- [Specifying the proxied service](#specifying-the-proxied-service)
- [Specifying the subdomain](#specifying-the-subdomain)
- [Specifying the protocol of the proxied service](#specifying-the-protocol-of-the-proxied-service)
- [Specifying authentication parameters](#specifying-authentication-parameters)

## Installation

The Zenith client is a command-line application written in Python. It can be used either directly
via a
[console script](https://python-packaging.readthedocs.io/en/latest/command-line-scripts.html#the-console-scripts-entry-point)
or in a container.

If possible, using the container image is preferred as it minimises the potential issues
with dependencies and the environment.

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

## Usage

The Zenith client can be configured in three ways, in order of precedence:

  * Command-line arguments
  * Environment variables
  * Configuration file

The location of the configuration file can be specified using either the `--config` command-line
argument or the `ZENITH_CLIENT_CONFIG` environment variable, with `/etc/zenith/client.yaml`
used by default if present.

This section describes the most commonly used options. For a full list of the available options see
`zenith-client --help` or the
[Zenith client configuration object](../client/zenith/client/config.py).

## Specifying the Zenith SSHD server

The Zenith client connects to a Zenith SSHD server to establish a secure tunnel. To do this,
the client must be configured with the correct address and port for the Zenith SSHD server.
This is done with the following options:

  * `server_address`: The address of the Zenith server, e.g. `sshd.example.cloud` or `193.154.167.25`.
      * CLI argument: `--server-address`
      * Environment variable: `ZENITH_CLIENT__SERVER_ADDRESS`
  * `server_port`: The port of the Zenith server.
      * CLI argument: `--server-port`
      * Environment variable: `ZENITH_CLIENT__SERVER_PORT`
      * Default: `22`

## Specifying the proxied service

The Zenith client forwards traffic that arrives down the SSH tunnel to another, locally available
service. To do this, the Zenith client must be configured with an address and a port to which
traffic should be forwarded. This is done with the following options:

  * `forward_to_host`: The host to forward tunnel traffic to, e.g. `127.0.0.1`.
      * CLI argument: `--forward-to-host`
      * Environment variable: `ZENITH_CLIENT__FORWARD_TO_HOST`
      * Default: `localhost`
  * `forward_to_port`: The port to forward tunnel traffic to, e.g. `5000`.
      * CLI argument: `--forward-to-port`
      * Environment variable: `ZENITH_CLIENT__FORWARD_TO_PORT`
      * Default: `8000`

## Specifying the subdomain

Zenith will forward traffic from a subdomain to our client - this subdomain can either be specified
when creating the tunnel or Zenith will generate one for you.

  * `subdomain`: The subdomain to use, e.g. `v929br0a92ler4rgp1thjvoa9vv21i5l`.
      * CLI argument: `--subdomain`
      * Environment variable: `ZENITH_CLIENT__SUBDOMAIN`
      * Default: random

## Specifying the protocol of the proxied service

By default, Zenith assumes that the services being proxied use the HTTP protocol. If the service
implements TLS, then Zenith must be told to use HTTPS instead.

  * `backend_protocol`: The protocol of the proxied service, one of `http` or `https`.
      * CLI argument: `--backend-protocol`
      * Environment variable: `ZENITH_CLIENT__BACKEND_PROTOCOL`
      * Default: `http`

## Specifying authentication parameters

Zenith is able to enforce authentication by calling out to an external auth service. When
initiating a tunnel, the Zenith client can specify a dictionary of parameters that will be passed
to the auth service as headers of the form `x-auth-{key}: {value}` and can be used by the
authentication service to make a decision. For example, when used as part of the
[Azimuth portal](https://github.com/stackhpc/azimuth) Zenith clients can specify the OpenStack
project that they belong to and the Azimuth auth callout will ensure project membership before
permitting a request to proceed.

The Zenith client can also opt out of the external auth, even when it is configured at the server.
This can be useful for services that should be anonymously available or that enforce their
own alternative authentication.

  * `skip_auth`: Indicates if the external auth should be skipped for this client.
      * CLI argument: `--skip-auth`
      * Environment variable: `ZENITH_CLIENT__SKIP_AUTH`
      * Default: `false`
  * `auth_params`: Indicates if the external auth should be skipped for this client.
      * CLI argument: `--auth-params`, accepts a JSON-formatted string
      * Environment variables of the form `ZENITH_CLIENT__AUTH_PARAMS__{KEY}`, e.g.
        `ZENITH_CLIENT__AUTH_PARAMS__OPENSTACK_PROJECT`
      * Default: `{}`
