import base64
import contextlib
import dataclasses
import json
import signal
import socket
import sys
import time
import typing
import uuid

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from pydantic import BaseModel, Extra, Field, conint, constr, root_validator, validator
import requests


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
    #: Parameters for the proxy authentication service
    auth_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
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

    @root_validator()
    def validate(cls, values):
        # Chain file and key file must be given together or not at all
        tls_cert = values.get("tls_cert")
        tls_key = values.get("tls_key")
        if tls_cert and not tls_key:
            raise ValueError("TLS key is required if TLS cert is specified")
        return values

    @validator("allocated_port")
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

    @validator("tls_cert")
    def validate_tls_cert(cls, v):
        """
        Validate the given value decoding it and trying to load it as a
        PEM-encoded X509 certificate.
        """
        _ = load_pem_x509_certificate(base64.b64decode(v))
        return v

    @validator("tls_key")
    def validate_tls_key(cls, v):
        """
        Validate the given value by decoding it and trying to load it as a
        PEM-encoded private key.
        """
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
def timeout(seconds):
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


def get_tunnel_config(timeout_secs):
    """
    Returns a config object for the tunnel.
    """
    print("[SERVER] [INFO] Waiting for configuration")
    # A well behaved client should take very little time to negotiate the tunnel config
    # So we timeout if it takes too long
    try:
        with timeout(timeout_secs):
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
        print(
            "[SERVER] [ERROR] Timed out negotiating tunnel configuration",
            file = sys.stderr
        )
        sys.exit(1)
    # The configuration should be base64-encoded JSON
    config = json.loads(base64.decodebytes("".join(input_lines).encode()))
    # We confirm that we received the configuration by sending another marker
    print("RECEIVED_CONFIGURATION")
    print(f"[SERVER] [INFO] Received configuration: {json.dumps(config, indent = 2)}")
    sys.stdout.flush()
    return Tunnel(
        # Generate a unique ID for the tunnel
        id = str(uuid.uuid4()),
        # Try to parse and validate the received configuration
        config = ClientConfig.parse_obj(config)
    )


def consul_check_service_host_and_port(server_config, tunnel):
    """
    Checks that there is not already an existing service with the same host and port.

    This protects against the case where a badly behaved client reports a different port
    to the one that was assigned to them.
    """
    print("[SERVER] [INFO] Checking if Consul service already exists for allocated port")
    url = f"{server_config.consul_url}/v1/agent/services"
    params = dict(
        filter = (
            f"Address == \"{server_config.service_host}\" and "
            f"Port == \"{tunnel.config.allocated_port}\" and "
            f"\"{server_config.service_tag}\" in Tags"
        )
    )
    response = requests.get(url, params = params)
    if 300 <= response.status_code < 200:
        print("[SERVER] [ERROR] Failed to list existing services", file = sys.stderr)
        sys.exit(1)
    # The response should be empty, otherwise the tunnel is not allowed
    if response.json():
        print("[SERVER] [ERROR] Service already exists for specified port", file = sys.stderr)
        sys.exit(1)
    else:
        print("[SERVER] [INFO] No existing service found")


def consul_register_service(server_config, tunnel, subdomain):
    """
    Registers the service with Consul.
    """
    # First, try to post any TLS configuration to the KV store
    tls_config = {}
    if tunnel.config.tls_cert:
        tls_config.update({
            "tls-cert": tunnel.config.tls_cert,
            "tls-key": tunnel.config.tls_key,
        })
    if tunnel.config.tls_client_ca:
        tls_config["tls-client-ca"] = tunnel.config.tls_client_ca
    if tls_config:
        print("[SERVER] [INFO] Posting TLS configuration to Consul")
        url = "{consul_url}/v1/kv/{key_prefix}/{tunnel_id}".format(
            consul_url = server_config.consul_url,
            key_prefix = server_config.consul_key_prefix,
            tunnel_id = tunnel.id
        )
        response = requests.put(url, json = tls_config)
        if 200 <= response.status_code < 300:
            print("[SERVER] [INFO] Posted TLS configuration successfully")
        else:
            print("[SERVER] [ERROR] Failed to post TLS configuration", file = sys.stderr)
            sys.exit(1)
    print("[SERVER] [INFO] Registering service with Consul")
    # Build the service metadata object
    metadata = { server_config.backend_protocol_metadata_key: tunnel.config.backend_protocol }
    if tunnel.config.read_timeout:
        metadata[server_config.read_timeout_metadata_key] = str(tunnel.config.read_timeout)
    if tunnel.config.skip_auth:
        metadata[server_config.skip_auth_metadata_key] = "1"
    elif tunnel.config.auth_params:
        metadata.update({
            f"{server_config.auth_param_metadata_prefix}{key}": value
            for key, value in tunnel.config.auth_params.items()
        })
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
            # Associate any required metadata
            "Meta": metadata,
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
        print("[SERVER] [INFO] Registered service successfully")
    else:
        print("[SERVER] [ERROR] Failed to register service", file = sys.stderr)
        sys.exit(1)


def consul_deregister_service(server_config, tunnel):
    """
    Deregisters the service in Consul.

    If this fails, the service will be marked critical after the TTL and removed
    after the deregister interval anyway, but this speeds up the process in the
    case where the client disconnects or we are given a chance to exit gracefully.

    We also attempt to remove any TLS configuration for the tunnel. We don't mind
    too much if this fails, e.g. if there is no TLS configuration - because each
    tunnel gets a unique id, the worst case scenario is that an unused TLS
    configuration is left behind in Consul.
    """
    requests.put(f"{server_config.consul_url}/v1/agent/service/deregister/{tunnel.id}")
    requests.delete("{consul_url}/v1/kv/{key_prefix}/{tunnel_id}".format(
        consul_url = server_config.consul_url,
        key_prefix = server_config.consul_key_prefix,
        tunnel_id = tunnel.id
    ))


class LivenessCheckFailed(Exception):
    """
    Exception that is raised when a liveness check failed.
    """


def liveness_check(tunnel):
    """
    Executes a liveness check for the tunnel and raises an exception with a message on failure.
    """
    proto = tunnel.config.backend_protocol
    port = tunnel.config.allocated_port
    path = tunnel.config.liveness_path
    liveness_url = f"{proto}://127.0.0.1:{port}{path}"
    print(f"[SERVER] [INFO] Executing liveness check using {liveness_url}")
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
    server_config,
    tunnel,
    consul_failures,
    liveness_failures,
    liveness_succeeded_once
):
    """
    Updates the health check for the service depending on a query to the liveness endpoint.
    """
    status = "passing"
    if tunnel.config.liveness_path:
        try:
            liveness_check(tunnel)
        except LivenessCheckFailed as exc:
            print(f"[SERVER] [WARN] Liveness check failed: {exc}", file = sys.stderr)
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
    print(f"[SERVER] [INFO] Updating service health status to '{status}' in Consul")
    # Post the service information to consul
    response = requests.put(
        f"{server_config.consul_url}/v1/agent/check/update/{tunnel.id}",
        json = { "Status": status }
    )
    if 200 <= response.status_code < 300:
        print("[SERVER] [INFO] Service health updated successfully")
        # Reset the Consul failures on success
        return 0, liveness_failures, liveness_succeeded_once
    else:
        # If we failed to update the health status, emit a warning
        print("[SERVER] [WARNING] Failed to update service health", file = sys.stderr)
    # Increment the failures if less than the limit
    if consul_failures < server_config.consul_heartbeat_failures:
        return consul_failures + 1, liveness_failures, liveness_succeeded_once
    # Otherwise, exit the process with an error status
    print(
        f"[SERVER] [ERROR] Failed to post status to Consul after {consul_failures} attempts",
        file = sys.stderr
    )
    sys.exit(1)


def register_signal_handlers(server_config, tunnel):
    """
    Registers signal handlers for each of the exit signals we care about.
    """
    def signal_handler(signum, frame):
        consul_deregister_service(server_config, tunnel)
        sys.exit()

    signal.signal(signal.SIGALRM, signal_handler)
    # The remote end hanging up should be a SIGHUP
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


def run(server_config, subdomain):
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
    print(f"[SERVER] [INFO] Initiating tunnel for subdomain '{subdomain}'")
    try:
        tunnel = get_tunnel_config(server_config.configure_timeout)
        consul_check_service_host_and_port(server_config, tunnel)
        consul_register_service(server_config, tunnel, subdomain)
        register_signal_handlers(server_config, tunnel)
        # We need to send a regular heartbeat to Consul
        # The heartbeat interval depends on whether a liveness check is configured
        if tunnel.config.liveness_path:
            heartbeat_interval = tunnel.config.liveness_period
        else:
            heartbeat_interval = server_config.consul_heartbeat_interval
        consul_failures = 0
        liveness_failures = 0
        liveness_succeeded_once = False
        with open('/var/log/zenith.log', 'at') as f:
            print(f"[INFO] tunnel starting heartbeach for {subdomain}", f)
        while True:
            consul_failures, liveness_failures, liveness_succeeded_once = consul_heartbeat(
                server_config,
                tunnel,
                consul_failures,
                liveness_failures,
                liveness_succeeded_once
            )
            time.sleep(heartbeat_interval)
    except Exception as e:
        with open('/var/log/zenith.log', 'at') as f:
            print(f"[ERROR] tunnel run for {subdomain} failed: {e}", f)
        raise
