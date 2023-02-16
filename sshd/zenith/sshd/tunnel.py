import base64
import contextlib
import dataclasses
import json
import logging
import signal
import socket
import sys
import time
import typing

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pydantic import (
    BaseModel,
    Extra,
    Field,
    AnyHttpUrl,
    conint,
    constr,
    validator
)

import requests

from .config import SSHDConfig


class TunnelError(RuntimeError):
    """
    Raised when there is an error with the tunnel.
    """


class TunnelExit(RuntimeError):
    """
    Raised to exit the tunnel without signifying an error.
    """

#: Type for an OIDC allowed group
AllowedGroup = constr(regex = r"^[a-zA-Z0-9_/-]+$")

#: Type for a key in the authentication parameters
#: This will become a header name, so limit to lowercase alpha-numeric + -
#: Although HTTP specifies no size limit, we do for readability
AuthParamsKey = constr(regex = r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 50)
#: Type for a value in the authentication parameters
#: Must fit in an HTTP header, so limited to 1024 unicode characters (4KB)
AuthParamsValue = constr(max_length = 1024)

#: Type for an RFC3986 compliant URL path component
UrlPath = constr(regex = r"/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]*", min_length = 1)


class ClientConfig(BaseModel):
    """
    Object for validating the client configuration.
    """
    class Config:
        extra = Extra.forbid

    #: The port for the service (the tunnel port)
    allocated_port: int
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https"] = "http"
    #: The read timeout for the service (in seconds)
    read_timeout: typing.Optional[conint(gt = 0)] = None
    #: Indicates whether the proxy authentication should be skipped
    skip_auth: bool = False
    #: The URL of the OIDC issuer to use
    auth_oidc_issuer: typing.Optional[AnyHttpUrl] = None
    #: The OIDC client ID to use
    auth_oidc_client_id: typing.Optional[constr(min_length = 1)] = None
    #: The OIDC client secret to use
    auth_oidc_client_secret: typing.Optional[constr(min_length = 1)] = None
    #: The OIDC groups that are allowed access to the the service
    #: The user must have at least one of these groups in their groups claim
    auth_oidc_allowed_groups: typing.List[AllowedGroup] = Field(default_factory = list)
    #: Parameters for the external authentication service (deprecated name)
    auth_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
    #: Parameters for the external authentication service
    auth_external_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
    #: Base64-encoded TLS certificate to use
    tls_cert: typing.Optional[str] = None
    #: Base64-encoded TLS private key to use (corresponds to TLS cert)
    tls_key: typing.Optional[str] = None
    #: Base64-encoded CA for validating TLS client certificates, if required
    tls_client_ca: typing.Optional[str] = None
    #: An optional liveness path
    liveness_path: typing.Optional[UrlPath] = None
    #: The period for liveness checks in seconds
    liveness_period: conint(gt = 0) = 10
    #: The number of liveness checks that can fail before the tunnel is considered unhealthy
    liveness_failures: conint(gt = 0) = 3

    @validator("allocated_port", always = True)
    def validate_port(cls, v):
        """
        Validate the given input as a port.
        """
        # The port must be an integer
        port = int(v)
        # The port must be in the registered port range
        if port < 1024 or port >= 49152:
            raise ValueError("Port must be in the registered port range")
        # The port must be in use for something
        # We validate this by trying to bind to it and catching the error
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind(("127.0.0.1", port))
            except OSError:
                # This is the condition we want
                return port
            else:
                raise ValueError("Given port is not in use")

    @validator("auth_external_params", pre = True, always = True)
    def validate_auth_external_params(cls, v, values, **kwargs):
        """
        Makes sure that the old name for external auth params is respected.
        """
        return v or values.get("auth_params", {})

    @validator("auth_oidc_issuer")
    def validate_auth_oidc_issuer(cls, v, values, **kwargs):
        """
        Validates that the OIDC issuer supports discovery.
        """
        issuer_url = v.rstrip("/")
        response = requests.get(f"{issuer_url}/.well-known/openid-configuration")
        if 200 <= response.status_code < 300:
            return v
        else:
            raise ValueError("OIDC issuer does not support discovery")

    @validator("auth_oidc_client_id", always = True)
    def validate_auth_oidc_client_id(cls, v, values, **kwargs):
        """
        Validates that an OIDC client id is given when an OIDC issuer is present.
        """
        skip_auth = values.get("skip_auth", False)
        oidc_issuer = values.get("auth_oidc_issuer")
        if not skip_auth and oidc_issuer and not v:
            raise ValueError("required for OIDC authentication")
        return v

    @validator("auth_oidc_client_secret", always = True)
    def validate_auth_oidc_client_secret(cls, v, values, **kwargs):
        """
        Validates that a client secret is given when a client ID is present.
        """
        skip_auth = values.get("skip_auth", False)
        oidc_issuer = values.get("auth_oidc_issuer")
        if not skip_auth and oidc_issuer and not v:
            raise ValueError("required for OIDC authentication")
        return v

    @validator("tls_cert")
    def validate_tls_cert(cls, v):
        """
        Validate the given value decoding it and trying to load it as a
        PEM-encoded X509 certificate.
        """
        _ = load_pem_x509_certificate(base64.b64decode(v))
        return v

    @validator("tls_key", always = True)
    def validate_tls_key(cls, v, values, **kwargs):
        """
        Validate the given value by decoding it and trying to load it as a
        PEM-encoded private key.
        """
        tls_cert = values.get("tls_cert")
        if tls_cert and not v:
            raise ValueError("required if TLS cert is specified")
        if v:
            _ = load_pem_private_key(base64.b64decode(v), None)
        return v

    @validator("tls_client_ca")
    def validate_tls_client_ca(cls, v):
        """
        Validate the given value by decoding it and trying to load it as a
        PEM-encoded X509 certificate.
        """
        _ = load_pem_x509_certificate(base64.b64decode(v))
        return v


@dataclasses.dataclass
class Tunnel:
    """
    Object representing the state of this tunnel.
    """
    #: The unqiue ID of the tunnel
    id: str
    # The configuration of the tunnel
    config: ClientConfig


def raise_timeout_error(signum, frame):
    """
    Utility function to raise a timeout error, used as a signal handler for the alarm signal.
    """
    raise TimeoutError


@contextlib.contextmanager
def timeout(seconds: int):
    """
    Context manager / decorator that imposes a timeout on the wrapped code.
    """
    previous = signal.signal(signal.SIGALRM, raise_timeout_error)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def get_tunnel_config(logger: logging.Logger, server_config: SSHDConfig) -> Tunnel:
    """
    Returns a config object for the tunnel.
    """
    logger.debug("Waiting for tunnel configuration")
    # A well behaved client should take very little time to negotiate the tunnel config
    # So we timeout if it takes too long
    try:
        with timeout(server_config.configure_timeout):
            # The configuration should be sent as JSON to stdin in response to the
            # marker "SEND_CONFIGURATION"
            # It could be one or multiple lines, but the line "END_CONFIGURATION" should
            # signify the end of the configuration
            print("SEND_CONFIGURATION")
            input_lines = []
            for line in sys.stdin:
                line = line.rstrip()
                if line == "END_CONFIGURATION":
                    break
                else:
                    input_lines.append(line)
    except TimeoutError:
        raise TunnelError("Timed out negotiating tunnel configuration")
    # The configuration should be base64-encoded JSON
    config = json.loads(base64.decodebytes("".join(input_lines).encode()))
    # We confirm that we received the configuration by sending another marker
    print("RECEIVED_CONFIGURATION")
    logger.info("Received tunnel configuration")
    sys.stdout.flush()
    # Parse the client data into a config object
    # This will raise validation errors if the config is incorrect
    tunnel_config = ClientConfig.parse_obj(config)
    logger.info(f"Allocated port for tunnel: {tunnel_config.allocated_port}")
    # Work out the TTL to use for the Consul session
    # This is the length of time after which keys created by the tunnel will be deleted if
    # we stop renewing the session
    # We use twice the heartbeat duration, which depends on the configured liveness check
    if tunnel_config.liveness_path:
        consul_session_ttl = tunnel_config.liveness_period * 2
    else:
        consul_session_ttl = server_config.consul_heartbeat_interval * 2
    # Start a Consul session for the tunnel
    logger.debug("Starting Consul session for tunnel")
    response = requests.put(
        f"{server_config.consul_url}/v1/session/create",
        json = {
            # Delete keys held by the session when the TTL expires
            "Behavior": "delete",
            # The TTL for the session - we must renew the session within this limit
            "TTL": f"{consul_session_ttl}s",
        }
    )
    if 200 <= response.status_code < 300:
        # The ID of the tunnel is the session ID
        tunnel_id = response.json()["ID"]
        logger.info(f"Assigned tunnel id: {tunnel_id}")
        return Tunnel(id = tunnel_id, config = tunnel_config)
    else:
        raise TunnelError("Failed to start Consul session for tunnel")


def consul_check_service_host_and_port(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel
):
    """
    Checks that there is not already an existing service with the same host and port.

    This protects against the case where a badly behaved client reports a different port
    to the one that was assigned to them.
    """
    logger.debug(
        "Checking if Consul service exists for '{host}:{port}'".format(
            host = server_config.service_host,
            port = tunnel.config.allocated_port
        )
    )
    url = f"{server_config.consul_url}/v1/agent/services"
    params = dict(
        filter = (
            f"Address == \"{server_config.service_host}\" and "
            f"Port == \"{tunnel.config.allocated_port}\" and "
            f"\"{server_config.service_tag}\" in Tags"
        )
    )
    response = requests.get(url, params = params)
    if 200 <= response.status_code < 300:
        # The response should be empty, otherwise the tunnel is not allowed
        if response.json():
            raise TunnelError(
                "Consul service already exists for '{host}:{port}'".format(
                    host = server_config.service_host,
                    port = tunnel.config.allocated_port
                )
            )
        else:
            logger.debug("No existing Consul service found")
    else:
        raise TunnelError("Failed to list Consul services")


def consul_post_config(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel
):
    """
    Posts any configuration for the tunnel to the KV store.
    """
    # Build the service metadata object
    config = { "backend-protocol": tunnel.config.backend_protocol }
    if tunnel.config.read_timeout:
        config["read-timeout"] = tunnel.config.read_timeout
    config["skip-auth"] = tunnel.config.skip_auth
    if not tunnel.config.skip_auth:
        if tunnel.config.auth_oidc_issuer:
            config.update({
                "auth-oidc-issuer": tunnel.config.auth_oidc_issuer,
                "auth-oidc-client-id": tunnel.config.auth_oidc_client_id,
                "auth-oidc-client-secret": tunnel.config.auth_oidc_client_secret,
                "auth-oidc-allowed-groups": tunnel.config.auth_oidc_allowed_groups,
            })
        elif tunnel.config.auth_external_params:
            config["auth-external-params"] = tunnel.config.auth_external_params
    if tunnel.config.tls_cert:
        config.update({
            "tls-cert": tunnel.config.tls_cert,
            "tls-key": tunnel.config.tls_key,
        })
    if tunnel.config.tls_client_ca:
        config["tls-client-ca"] = tunnel.config.tls_client_ca
    logger.debug("Posting tunnel configuration to Consul")
    # Associate the config key with the tunnel's session
    url = "{consul_url}/v1/kv/{key_prefix}/{tunnel_id}?acquire={tunnel_id}".format(
        consul_url = server_config.consul_url,
        key_prefix = server_config.consul_key_prefix,
        tunnel_id = tunnel.id
    )
    response = requests.put(url, json = config)
    if 200 <= response.status_code < 300:
        logger.info("Tunnel configuration posted to Consul")
    else:
        raise TunnelError("Failed to post tunnel configuration to Consul")


def consul_register_service(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel,
    subdomain: str
):
    """
    Registers the service with Consul.
    """
    logger.debug("Registering service with Consul")
    # Work out the TTL to use
    # This is the length of time after which a service will be moved into the critical state
    # if we stop posting status updates
    # We use twice the heartbeat duration, which depends on the configured liveness check
    if tunnel.config.liveness_path:
        consul_service_ttl = tunnel.config.liveness_period * 2
    else:
        consul_service_ttl = server_config.consul_heartbeat_interval * 2
    # Post the service information to consul
    response = requests.put(
        f"{server_config.consul_url}/v1/agent/service/register",
        json = {
            # Use the tunnel ID as the unique id
            "ID": tunnel.id,
            # Use the specified subdomain as the service name
            "Name": subdomain,
            # Use the service host and port as the address and port in Consul
            "Address": server_config.service_host,
            "Port": tunnel.config.allocated_port,
            # Tag the service as a Zenith service
            "Tags": [server_config.service_tag],
            # Specify a TTL check
            "Check": {
                # Use the unique ID for the tunnel as the check id
                "CheckId": tunnel.id,
                "Name": "tunnel-active",
                # Use a TTL health check
                # This will move into the critical state, removing the service from
                # the proxy, if we do not post a status update within the TTL
                "TTL": f"{consul_service_ttl}s",
                # This deregisters the service once it has been critical for the specified interval
                # We can probably assume the service will not come back up
                "DeregisterCriticalServiceAfter": f"{server_config.consul_deregister_interval}s",
            },
        }
    )
    # If we failed to register the service then bail
    if 200 <= response.status_code < 300:
        logger.info("Registered service with Consul")
    else:
        raise TunnelError("Failed to register service with Consul")


def consul_deregister_service(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel
):
    """
    Deregisters the service in Consul.

    If this fails, the service will be marked critical after the TTL and removed
    after the deregister interval anyway, but this speeds up the process in the
    case where the client disconnects or we are given a chance to exit gracefully.

    We also attempt to remove any configuration for the tunnel. We don't mind too much
    if any of these requests fail because the service has a TTL and the config key is
    associated with a session that also has a TTL.
    """
    logger.debug("Removing service from Consul")
    requests.put(f"{server_config.consul_url}/v1/agent/service/deregister/{tunnel.id}")
    logger.debug("Removing configuration from Consul KV")
    requests.delete("{consul_url}/v1/kv/{key_prefix}/{tunnel_id}".format(
        consul_url = server_config.consul_url,
        key_prefix = server_config.consul_key_prefix,
        tunnel_id = tunnel.id
    ))
    logger.debug("Terminating Consul session")
    requests.put(f"{server_config.consul_url}/v1/session/destroy/{tunnel.id}")


class LivenessCheckFailed(Exception):
    """
    Exception that is raised when a liveness check failed.
    """


def liveness_check(logger:logging.Logger, tunnel: Tunnel):
    """
    Executes a liveness check for the tunnel and raises an exception with a message on failure.
    """
    proto = tunnel.config.backend_protocol
    port = tunnel.config.allocated_port
    path = tunnel.config.liveness_path
    liveness_url = f"{proto}://127.0.0.1:{port}{path}"
    logger.debug(f"Executing liveness check using {liveness_url}")
    try:
        # It is not our job to verify SSL certificates - that is for the eventual destination,
        # e.g. a user's browser, to decide
        response = requests.get(liveness_url, verify = False)
    except Exception as exc:
        raise LivenessCheckFailed(repr(exc))
    else:
        if response.status_code >= 500:
            raise LivenessCheckFailed(repr(response))


def consul_heartbeat(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel,
    consul_failures: int,
    liveness_failures: int,
    liveness_succeeded_once: bool
):
    """
    Updates the health check for the service depending on a query to the liveness endpoint.
    """
    status = "passing"
    if tunnel.config.liveness_path:
        try:
            liveness_check(tunnel)
        except LivenessCheckFailed as exc:
            logger.warning(f"Liveness check failed: {exc}")
            liveness_failures = liveness_failures + 1
        else:
            # When the check passes, reset the failure count
            liveness_failures = 0
            liveness_succeeded_once = True
        if liveness_failures >= tunnel.config.liveness_failures:
            status = "critical"
        elif liveness_failures > 0:
            # We want services to stay in the critical state until they succeed at least once
            status = "warning" if liveness_succeeded_once else "critical"
    # Post the service information to Consul and renew the session
    logger.debug(f"Updating Consul service status to '{status}'")
    status_response = requests.put(
        f"{server_config.consul_url}/v1/agent/check/update/{tunnel.id}",
        json = { "Status": status }
    )
    logger.debug(f"Renewing Consul session")
    renew_response = requests.put(f"{server_config.consul_url}/v1/session/renew/{tunnel.id}")
    # Reset the Consul failures on success
    if 200 <= status_response.status_code < 300 and 200 <= renew_response.status_code < 300:
        logger.info(f"Updated Consul service status to '{status}'")
        logger.info("Renewed Consul session for tunnel")
        return 0, liveness_failures, liveness_succeeded_once
    elif status_response.status_code < 200 or status_response.status_code >= 300:
        logger.warning("Failed to update Consul service status")
    else:
        logger.warning("Failed to renew Consul session for tunnel")
    # Increment the failures if less than the limit
    if consul_failures < server_config.consul_heartbeat_failures:
        return consul_failures + 1, liveness_failures, liveness_succeeded_once
    # Otherwise, exit the process with an error status
    raise TunnelError(f"Failed to update Consul service health after {consul_failures} attempts")


def register_signal_handlers(
    server_config: SSHDConfig,
    logger: logging.Logger,
    tunnel: Tunnel
):
    """
    Registers signal handlers for each of the exit signals we care about.
    """
    def signal_handler(signum, frame):
        consul_deregister_service(server_config, logger, tunnel)
        raise TunnelExit()

    signal.signal(signal.SIGALRM, signal_handler)
    # The remote end hanging up should be a SIGHUP
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def run(server_config: SSHDConfig, subdomain: str):
    """
    This function is called when a user connects over SSH, and is responsible for
    registering the mapping of a subdomain to the port for a reverse SSH tunnel
    with Consul.

    The subdomain is determined by the SSH public key that the client connected with.

    The client specifies the bound port, and other tunnel configuration, using stdin.

    We would prefer to detect the bound port for the tunnel on this side but
    doing this reliably might be impossible, and is certainly very difficult
    and probably requires root.

    To get round this, the client reads the tunnel's dynamically-allocated port
    from stderr and pushes it back via stdin along with other configuration.

    This obviously places a lot of trust in a client to specify the SSH
    connection correctly, and also to specify the actual port it was allocated
    rather than a different port that another service may be connected to.

    We mitigate against this in a number of ways:

      1. Only allow the execution of this script over the SSH connection. This
         limits the ability of a nefarious client to collect information about
         other tunnels connected to the system and their ports.

      2. Encourage clients to use dynamically-allocated ports. This makes the
         port for a service more difficult to guess and so harder to connect
         to for nefarious purposes.

      3. Subdomains are bound to pre-registered SSH keys. A client can only connect
         to SSHD using a pre-registered SSH key, and the subdomain they can use
         is bound to that SSH key. The public key(s) for a subdomain are bound
         using a single-use token that is issued by the Zenith registrar. This
         prevents a potentially malicious client from connecting at all unless
         they have an SSH key bound to a domain, and prevents them from binding to
         a domain other than the one they were allocated.

      3. Only allow reverse port-forwarding, not regular port-forwarding. This
         prevents a nefarious client from setting up a regular port-foward to
         the bound port for another service and sending traffic directly to it,
         bypassing the proxy and any associated authentication.

      5. Only allow a domain to be bound to a port that is listening. This
         prevents a nefarious client from binding their domain to a port that
         is not yet in use in the hope of intercepting traffic in the future.

      6. Only allow one domain to be bound to each port. This prevents a nefarious
         client from binding their subdomain to an existing tunnel in order to
         intercept traffic.
    """
    actual_logger = logging.getLogger(__name__)
    # Add the subdomain to the logging context
    logger = logging.LoggerAdapter(
        actual_logger,
        {"subdomain": subdomain, "tunnelid": ""}
    )
    logger.info("Initiating tunnel")
    try:
        tunnel = get_tunnel_config(logger, server_config)
        # Now we know the tunnel id, replace the logger
        logger = logging.LoggerAdapter(
            actual_logger,
            {"subdomain": subdomain, "tunnelid": tunnel.id}
        )
        consul_check_service_host_and_port(server_config, logger, tunnel)
        consul_post_config(server_config, logger, tunnel)
        consul_register_service(server_config, logger, tunnel, subdomain)
        register_signal_handlers(server_config, logger, tunnel)
        # We need to send a regular heartbeat to Consul
        # The heartbeat interval depends on whether a liveness check is configured
        if tunnel.config.liveness_path:
            heartbeat_interval = tunnel.config.liveness_period
        else:
            heartbeat_interval = server_config.consul_heartbeat_interval
        consul_failures = 0
        liveness_failures = 0
        liveness_succeeded_once = False
        while True:
            consul_failures, liveness_failures, liveness_succeeded_once = consul_heartbeat(
                server_config,
                logger,
                tunnel,
                consul_failures,
                liveness_failures,
                liveness_succeeded_once
            )
            time.sleep(heartbeat_interval)
    except TunnelExit:
        logger.info("Tunnel disconnected by client")
        # This should lead to a clean exit
    except Exception:
        logger.exception("Exception raised by tunnel")
        sys.exit(1)
