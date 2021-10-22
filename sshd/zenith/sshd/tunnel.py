#!/usr/bin/env python3

import contextlib
import dataclasses
import signal
import socket
import sys
import time
import typing
import uuid

from pydantic import BaseModel, Field, constr, validator
import requests


#: Constraint for a Consul metadata key
MetadataKey = constr(regex = r"^[a-zA-Z0-9_-]+$", max_length = 128)
#: Constraint for a Consul metadata value
MetadataValue = constr(max_length = 512)


class ClientConfig(BaseModel):
    """
    Object for validating the client configuration.
    """
    #: The port for the service (the tunnel port)
    allocated_port: int
    #: The subdomain to use
    #: Subdomains must be at most 63 characters long, can only contain alphanumeric characters
    #: and hyphens, and cannot start or end with a hyphen
    #: In addition, Kubernetes service names cannot start with a number and must be lower case
    #: See https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#rfc-1035-label-names
    subdomain: constr(regex = r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 63)
    #: Metadata for the tunnel
    metadata: typing.Dict[MetadataKey, MetadataValue] = Field(default_factory = dict)

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

    @validator("metadata")
    def validate_metadata(cls, v):
        """
        Validates the given input as a metadata dict.
        """
        if len(v) > 64:
            raise ValueError("at most 64 metadata items are permitted")
        else:
            return v


@dataclasses.dataclass
class TunnelConfig:
    """
    Object representing the configuration for this tunnel.
    """
    #: The ID of the service, unique to this tunnel
    service_id: str
    #: The port for the service (the tunnel port)
    service_port: int
    #: The subdomain to use
    subdomain: str
    #: Metadata for the tunnel
    metadata: typing.Dict[str, str]

    @classmethod
    def from_client_config(cls, config):
        return cls(
            service_id = str(uuid.uuid4()),
            service_port = config.allocated_port,
            subdomain = config.subdomain,
            metadata = config.metadata
        )


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
    print("[SERVER] [INFO] Waiting for configuration...")
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
    # We confirm that we received the configuration by sending another marker
    print("RECEIVED_CONFIGURATION")
    print(f"[SERVER] [INFO] Received configuration: {''.join(input_lines)}")
    sys.stdout.flush()
    # Try to parse the received configuration as JSON
    client_config = ClientConfig.parse_raw("".join(input_lines))
    return TunnelConfig.from_client_config(client_config)


def consul_check_service_host_and_port(server_config, tunnel_config):
    """
    Checks that there is not already an existing service with the same host and port.

    This protects against the case where a badly behaved client reports a different port
    to the one that was assigned to them.
    """
    print("[SERVER] [INFO] Checking if Consul service already exists for allocated port...")
    url = f"{server_config.consul_url}/v1/agent/services"
    params = dict(
        filter = (
            f"Address == \"{server_config.service_host}\" and "
            f"Port == \"{tunnel_config.service_port}\" and "
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


def consul_register_service(server_config, tunnel_config):
    """
    Registers the service with Consul.
    """
    print("[SERVER] [INFO] Registering service with Consul...")
    # Post the service information to consul
    url = f"{server_config.consul_url}/v1/agent/service/register"
    response = requests.put(url, json = {
        # Use the tunnel ID as the unique id
        "ID": tunnel_config.service_id,
        # Use the specified subdomain as the service name
        "Name": tunnel_config.subdomain,
        # Use the service host and port as the address and port in Consul
        "Address": server_config.service_host,
        "Port": tunnel_config.service_port,
        # Tag the service as a tunnel proxy subdomain
        "Tags": [server_config.service_tag],
        # Associate any specified metadata
        "Meta": tunnel_config.metadata,
        # Specify a TTL check
        "Check": {
            # Use the unique ID for the tunnel as the check id
            "CheckId": tunnel_config.service_id,
            "Name": "tunnel-active",
            # Use a TTL health check
            # This will move into the critical state, removing the service from
            # the proxy, if we do not post a status update within the TTL
            "TTL": server_config.consul_service_ttl,
            # This deregisters the service once it has been critical for 5 minutes
            # We can probably assume the service will not come back up
            "DeregisterCriticalServiceAfter": server_config.consul_deregister_interval,
        },
    })
    # If we failed to register the service then bail
    if 200 <= response.status_code < 300:
        print("[SERVER] [INFO] Registered service successfully")
    else:
        print("[SERVER] [ERROR] Failed to register service", file = sys.stderr)
        sys.exit(1)


def consul_deregister_service(server_config, tunnel_config):
    """
    Deregisters the service in Consul.

    We don't really care if this fails because the service will be marked critical
    after the TTL and removed after the deregister interval anyway, but this speeds
    up the process in the case where the client disconnects or we are given a
    chance to exit gracefully.
    """
    url = f"{server_config.consul_url}/v1/agent/service/deregister/{tunnel_config.service_id}"
    requests.put(url)


def consul_heartbeat(server_config, tunnel_config, failures):
    """
    Updates the health check for the service to the pass state.
    """
    print("[SERVER] [INFO] Updating service health status in Consul...")
    # Post the service information to consul
    url = f"{server_config.consul_url}/v1/agent/check/pass/{tunnel_config.service_id}"
    response = requests.put(url, params = { "note": "Tunnel active" })
    if 200 <= response.status_code < 300:
        print("[SERVER] [INFO] Service health updated successfully")
        # Reset the failures on success
        return 0
    else:
        # If we failed to update the health status, emit a warning
        print("[SERVER] [WARNING] Failed to update service health", file = sys.stderr)
    # Increment the failures if less than the limit
    if failures < server_config.consul_heartbeat_failures:
        return failures + 1
    # Otherwise, exit the process with an error status
    print("[SERVER] [ERROR] Maximum permitted number of failures reached", file = sys.stderr)
    sys.exit(1)


def register_signal_handlers(server_config, tunnel_config):
    """
    Registers signal handlers for each of the exit signals we care about.
    """
    def signal_handler(signum, frame):
        consul_deregister_service(server_config, tunnel_config)
        sys.exit()

    signal.signal(signal.SIGALRM, signal_handler)
    # The remote end hanging up should be a SIGHUP
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # We deliberately ignore SIGKILL as that is meant to signal an ungraceful exit
    # It is also not supported on some platforms, e.g. OSX
    # Any well-behaved exit request should be SIGTERM


def run(server_config):
    """
    This function is called when a user connects over SSH, and is responsible for
    registering the mapping of a subdomain to the port for a reverse SSH tunnel
    with Consul.

    The client specifies the bound port and subdomain using stdin.

    We would prefer to detect the bound port for the tunnel on this side but
    doing this reliably might be impossible, and is certainly very difficult
    and probably requires root.

     To get round this, the client reads the tunnel's dynamically-allocated port
    from stderr and pushes it back via stdin along with the subdomain.

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

      3. Encourage clients to use subdomains that are hard to guess.
         This makes it more difficult for a nefarious client to discover a valid
         domain and bind to it.

      4. Only allow reverse port-forwarding, not regular port-forwarding. This
         prevents a nefarious client from setting up a regular port-foward to
         the bound port for another service and sending traffic directly to it,
         bypassing the proxy and any associated authentication.

      5. Only allow a domain to be bound to a port that is listening. This
         prevents a nefarious client from binding a known domain to a port that
         is not yet in use in the hope of intercepting traffic in the future.

      6. Only allow one domain to be bound to each tunnel. This prevents a
         nefarious client from binding an additional domain that is known to
         them to an existing tunnel in order to intercept traffic.
    """
    tunnel_config = get_tunnel_config(server_config.configure_timeout)   
    consul_check_service_host_and_port(server_config, tunnel_config)
    consul_register_service(server_config, tunnel_config)
    register_signal_handlers(server_config, tunnel_config)
    # We need to send a regular heartbeat to Consul
    failures = 0
    while True:
        failures = consul_heartbeat(server_config, tunnel_config, failures)
        time.sleep(server_config.consul_heartbeat_interval)
