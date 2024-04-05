import base64
import contextlib
import json
import logging
import signal
import sys
import time
import typing

import requests

from . import backends, config, models


class TunnelError(RuntimeError):
    """
    Raised when there is an error with the tunnel.
    """


class TunnelExit(RuntimeError):
    """
    Raised to exit the tunnel without signifying an error.
    """


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


def get_tunnel_config(
    logger: logging.Logger,
    server_config: config.SSHDConfig
) -> models.ClientConfig:
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
    tunnel_config = models.ClientConfig.model_validate(config)
    logger.info(f"Allocated port for tunnel: {tunnel_config.allocated_port}")
    return tunnel_config


class LivenessCheckFailed(Exception):
    """
    Exception that is raised when a liveness check failed.
    """


def liveness_check(logger:logging.Logger, client_config: models.ClientConfig):
    """
    Executes a liveness check for the tunnel and raises an exception with a message on failure.
    """
    proto = client_config.backend_protocol
    port = client_config.allocated_port
    path = client_config.liveness_path
    liveness_url = f"{proto}://127.0.0.1:{port}{path}"
    logger.debug(f"Executing liveness check using {liveness_url}")
    try:
        # It is not our job to verify SSL certificates - that is for the eventual destination,
        # e.g. a user's browser, to decide
        response = requests.get(liveness_url, verify = False)
    except TunnelExit:
        # If TunnelExit is raised by a signal, re-raise it without any other action
        raise
    except Exception as exc:
        raise LivenessCheckFailed(repr(exc))
    else:
        if response.status_code >= 500:
            raise LivenessCheckFailed(repr(response))


def heartbeat(
    logger: logging.Logger,
    backend: backends.Backend,
    server_config: config.SSHDConfig,
    client_config: models.ClientConfig,
    subdomain: str,
    tunnel_id: str,
    heartbeat_failures: int,
    liveness_failures: int,
    liveness_succeeded_once: bool
) -> typing.Tuple[int, int, bool]:
    """
    Updates the health check for the service depending on a query to the liveness endpoint.
    """
    status = backends.TunnelStatus.PASSING
    if client_config.liveness_path:
        try:
            liveness_check(logger, client_config)
        except LivenessCheckFailed as exc:
            logger.warning(f"Liveness check failed: {exc}")
            liveness_failures = liveness_failures + 1
        else:
            # When the check passes, reset the failure count
            liveness_failures = 0
            liveness_succeeded_once = True
        if liveness_failures >= client_config.liveness_failures:
            status = backends.TunnelStatus.CRITICAL
        elif liveness_failures > 0:
            # We want services to stay in the critical state until they succeed at least once
            status = (
                backends.TunnelStatus.WARNING
                if liveness_succeeded_once
                else backends.TunnelStatus.CRITICAL
            )
    # Post the heartbeat using the backend
    logger.debug(f"Posting heartbeat for tunnel with status '{status.value}'")
    try:
        backend.tunnel_heartbeat(subdomain, tunnel_id, status)
    except TunnelExit:
        # If TunnelExit is raised by a signal, re-raise it without any other action
        raise
    except Exception:
        heartbeat_failures = heartbeat_failures + 1
        # If we have reached the maximum number of failures, propagate the exception
        # If not, log the exception and increment the number of failures
        if heartbeat_failures >= server_config.heartbeat_failures:
            raise
        else:
            logger.exception(f"Failed to post heartbeat (attempt {heartbeat_failures})")
            return heartbeat_failures, liveness_failures, liveness_succeeded_once
    else:
        logger.info(f"Posted heartbeat with status '{status.value}'")
        # If the heartbeat was posted successfully, reset the failures
        return 0, liveness_failures, liveness_succeeded_once


def register_signal_handlers():
    """
    Registers signal handlers for each of the exit signals we care about.
    """
    def signal_handler(signum, frame):
        raise TunnelExit()

    signal.signal(signal.SIGALRM, signal_handler)
    # The remote end hanging up should be a SIGHUP
    signal.signal(signal.SIGHUP, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)


class ReconfigurableLoggerAdapter(logging.LoggerAdapter):
    """
    Variation of LoggerAdapter where the extra can be dynamically reconfigured.
    """
    def update_extra(self, extra):
        self.extra.update(extra)

    def process(self, msg, kwargs):
        kwargs["extra"] = {**self.extra, **kwargs.get("extra", {})}
        return msg, kwargs


def run(server_config: config.SSHDConfig, subdomain: str):
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
    # Initialise the logger
    logger = ReconfigurableLoggerAdapter(
        logging.getLogger(__name__),
        {"subdomain": subdomain, "tunnelid": ""}
    )
    try:
        # Initialise the backend from the config
        with backends.load(logger, server_config) as backend:
            logger.info("Negotiating tunnel configuration")
            # Get and verify the tunnel config
            client_config = get_tunnel_config(logger, server_config)
            # Check if there is already a service with the same host and port
            # This protects against the case where a badly behaved client reports
            # a different port to the one that was assigned to them
            logger.debug(
                "Checking if service exists for '{host}:{port}'".format(
                    host = server_config.service_host,
                    port = client_config.allocated_port
                )
            )
            if backend.tunnel_check_host_and_port(
                server_config.service_host,
                client_config.allocated_port
            ):
                logger.debug("No existing service found")
            else:
                raise TunnelError(
                    "Consul service already exists for '{host}:{port}'".format(
                        host = server_config.service_host,
                        port = client_config.allocated_port
                    )
                )
            # Work out the TTL to use, i.e. the length of time after which the tunnel will be
            # considered dead if we stop posting heartbeats
            if client_config.liveness_path:
                tunnel_ttl = client_config.liveness_period * 2
            else:
                tunnel_ttl = server_config.heartbeat_interval * 2
            # Initialise the tunnel
            logger.debug("Initialising tunnel")
            tunnel_id = backend.tunnel_init(
                subdomain,
                server_config.service_host,
                client_config.allocated_port,
                tunnel_ttl,
                server_config.reap_after,
                client_config.as_sync_config()
            )
            # Now we know the tunnel ID, reconfigure the logger
            logger.update_extra({ "tunnelid": tunnel_id })
            # Register the signal handlers to terminate the tunnel
            logger.debug("Registering signal handlers")
            register_signal_handlers()
            try:
                # We need to send a regular heartbeat
                # The heartbeat interval depends on whether a liveness check is configured
                if client_config.liveness_path:
                    heartbeat_interval = client_config.liveness_period
                else:
                    heartbeat_interval = server_config.heartbeat_interval
                heartbeat_failures = 0
                liveness_failures = 0
                liveness_succeeded_once = False
                while True:
                    heartbeat_failures, liveness_failures, liveness_succeeded_once = heartbeat(
                        logger,
                        backend,
                        server_config,
                        client_config,
                        subdomain,
                        tunnel_id,
                        heartbeat_failures,
                        liveness_failures,
                        liveness_succeeded_once
                    )
                    time.sleep(heartbeat_interval)
            except TunnelExit:
                # We want a clean exit in this case
                logger.info("Tunnel disconnected by client")
            finally:
                backend.tunnel_terminate(subdomain, tunnel_id)
    except Exception as exc:
        logger.exception(str(exc))
        sys.exit(1)
