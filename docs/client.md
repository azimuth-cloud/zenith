# Configuring the Zenith client  <!-- omit in toc -->

The Zenith client establishes a secure tunnel with a Zenith server and ensures that traffic received
over that tunnel is forwarded to the proxied service.

## Contents  <!-- omit in toc -->

- [Installation](#installation)
  - [Container image](#container-image)
  - [Python installation](#python-installation)
- [Resilience](#resilience)
- [Usage](#usage)
  - [Specifying the SSH identity](#specifying-the-ssh-identity)
  - [`init` command](#init-command)
  - [`connect` command](#connect-command)
    - [Specifying the Zenith SSHD server](#specifying-the-zenith-sshd-server)
    - [Specifying the proxied service](#specifying-the-proxied-service)
    - [Specifying the protocol of the proxied service](#specifying-the-protocol-of-the-proxied-service)
    - [Specifying authentication parameters](#specifying-authentication-parameters)
      - [OpenID Connect](#openid-connect)
      - [External auth](#external-auth)

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

## Resilience

When using the Zenith client to expose a long-running service, it is important to deploy the
client in a way that means it can automatically recover from failures. In general, it should be
assumed that the SSH tunnel established between a Zenith client and a Zenith server could fail at
any time due to issues with the server, the client or the network in-between.

In particular, it is important to run the Zenith client in such a way that it will be restarted if
it exits with an error condition. Typically this would be done using a supervising process, e.g. by
running the Zenith client as a [systemd service](https://en.wikipedia.org/wiki/Systemd) or using a
process monitor like [Supervisor](http://supervisord.org/). If you are running the Zenith client as
a Docker container, this can be achieved by setting an appropriate
[Docker restart policy](https://docs.docker.com/config/containers/start-containers-automatically/#use-a-restart-policy)
such as `on-failure` for the container.

## Usage

The Zenith client has two subcommands - `init` and `connect`. The `init` command is run once to
initialise the client by generating an SSH keypair, if required, and uploading the public key
to the registrar using the token supplied by the broker. The `connect` command then uses the
keypair registered by the `init` command to establish a secure tunnel for the proxied service.
The `connect` command can be run more than once.

The Zenith client can be configured in three ways, in order of precedence:

  * Command-line arguments
  * Environment variables
  * Configuration file

Not all options are available via the command line, so environment variables or a config file
are recommended for most situations.

The location of the configuration file can be specified using either the `--config` command-line
argument or the `ZENITH_CLIENT_CONFIG` environment variable, with `/etc/zenith/client.yaml`
used by default if present.

This section describes the most commonly used options. For a full list of the available options see
`zenith-client [init|connect] --help` or the
[Zenith client configuration objects](../client/zenith/client/config.py).

### Specifying the SSH identity

The `init` and `connect` commands both require access to the same SSH identity, specified as
a path. The `connect` command requires the identity to exist at the given path before it can run,
but the `init` command will generate a new keypair at the specified path if one does not exist.
The path to the SSH identity is specified using the following option:

  * `ssh_identity_path`: The path to the SSH identity to use, e.g. `$HOME/.ssh/id_zenith`.
    * CLI argument: `--ssh-identity-path`
    * Environment variable: `ZENITH_CLIENT__SSH_IDENTITY_PATH`
    * Default: *This option is required.*

### `init` command

The `init` command is responsible for uploading the client's public key to the Zenith registrar.
To do this, the `init` command must be configured with the URL for the Zenith registrar and
a token issued by the registrar for a reserved subdomain (via an implementation-specific broker).
This is done with the following options:

  * `registrar_url`: The URL of the Zenith registrar, e.g. `https://registrar.example.cloud`.
    * CLI argument: `--registrar-url`
    * Environment variable: `ZENITH_CLIENT__REGISTRAR_URL`
    * Default: *This option is required.*
  * `token`: The token issued by the Zenith registrar.
    * CLI argument: `--token`
    * Environment variable: `ZENITH_CLIENT__TOKEN`
    * Default: *This option is required.*

### `connect` command

#### Specifying the Zenith SSHD server

The Zenith client connects to a Zenith SSHD server to establish a secure tunnel. To do this,
the client must be configured with the correct address and port for the Zenith SSHD server.
This is done with the following options:

  * `server_address`: The address of the Zenith SSHD server, e.g. `sshd.example.cloud` or `193.154.167.25`.
      * CLI argument: `--server-address`
      * Environment variable: `ZENITH_CLIENT__SERVER_ADDRESS`
      * Default: *This option is required.*
  * `server_port`: The port of the Zenith SSHD server.
      * CLI argument: `--server-port`
      * Environment variable: `ZENITH_CLIENT__SERVER_PORT`
      * Default: `22`

#### Specifying the proxied service

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

#### Specifying the protocol of the proxied service

By default, Zenith assumes that the services being proxied use the HTTP protocol. If the service
implements TLS, then Zenith must be told to use HTTPS instead.

  * `backend_protocol`: The protocol of the proxied service, one of `http` or `https`.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variable: `ZENITH_CLIENT__BACKEND_PROTOCOL`
      * Default: `http`

#### Specifying authentication parameters

Zenith is able to enforce authentication, either using OpenID Connect (OIDC) or by calling out
to an external auth service.

A Zenith client can also opt out of any authentication that is imposed at the server. This can
be useful for services that should be anonymously available or that enforce their own authentication.

  * `skip_auth`: Indicates if authentication should be skipped for this client.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variable: `ZENITH_CLIENT__SKIP_AUTH`
      * Default: `false`

##### OpenID Connect

The Zenith server supports using OpenID Connect (OIDC) to provide authentication for proxied
services. This can be imposed on the server side using a discovery mechanism (see 
[Deploying and configuring a Zenith server](./server.md)), but clients are able to override
the OIDC parameters in order to use a specific OIDC issuer.

In order to do this, the client must have a client ID and secret from the target OIDC issuer.
Obtaining these credentials is out-of-scope of the Zenith components. The redirect URL of
the client must be `https://{allocated FQDN}/_oidc/callback`.

The given issuer URL should be such that the OpenID configuration can be discovered at
 `{auth_oidc_issuer}/.well-known/openid-configuration`.

  * `auth_oidc_issuer`: The URL of the OIDC issuer to use.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variable: `ZENITH_CLIENT__AUTH_OIDC_ISSUER`
      * Default: `None`
  * `auth_oidc_client_id`: The client ID of the OIDC client to use.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variable: `ZENITH_CLIENT__AUTH_OIDC_CLIENT_ID`
      * Default: `None`
  * `auth_oidc_client_secret`: The client secret of the OIDC client to use.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variable: `ZENITH_CLIENT__AUTH_OIDC_CLIENT_SECRET`
      * Default: `None`

##### External auth

When the server supports external auth, a Zenith client can specify a dictionary of parameters
that will be passed to the auth service as headers of the form `x-auth-{key}: {value}`. The
authentication service can then use these headers to make an authorization decision.

  * `auth_external_params`: Parameters for the external auth service.
      * CLI argument: *Not available as a CLI argument.*
      * Environment variables of the form `ZENITH_CLIENT__AUTH_EXTERNAL_PARAMS__{KEY}`, e.g.
        `ZENITH_CLIENT__AUTH_EXTERNAL_PARAMS__OPENSTACK_PROJECT`
      * Default: `{}`
