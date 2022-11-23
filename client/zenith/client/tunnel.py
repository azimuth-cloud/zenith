import base64
import contextlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import tempfile

from .config import AuthType


logger = logging.getLogger(__name__)


def get_allocated_port(output):
    """
    Extract the allocated port from the output stream.
    """
    for line in output:
        line = line.rstrip()
        match = re.match(r"Allocated port (?P<port>\d+) for remote forward", line)
        if match is not None:
            return int(match.group('port'))
        else:
            # If the line is not the one we need, send it to stderr
            print(line, file = sys.stderr)
    else:
        logger.error("[CLIENT] No port received from server")
        sys.exit(1)


def wait_for_marker(output, marker):
    """
    Waits for the given marker to appear on the output stream before returning.
    """
    for line in output:
        line = line.rstrip()
        if line == marker:
            break
        else:
            # If the line is not the one we need, send it to stdout
            print(line)
    else:
        logger.error("[CLIENT] Unable to find marker '%s'", marker)
        sys.exit(1)


def raise_timeout_error(signum, frame):
    """
    Utility function to raise a timeout error, used as a signal handler for the alarm signal.
    """
    raise TimeoutError


@contextlib.contextmanager
def timeout(seconds):
    """
    Context manager / decorator that imposes a timeout on the wrapped code.

    This context manager only works on Linux.

    When running on Windows it is a no-op due to the unavailability of SIGALRM.
    """
    if hasattr(signal, "SIGALRM"):
        previous = signal.signal(signal.SIGALRM, raise_timeout_error)
        signal.alarm(seconds)
    try:
        yield
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous)


def configure_tunnel(ssh_proc, config):
    """
    Configures the tunnel.
    """
    # If the server is behaving correctly configuring the tunnel should be quick,
    # so we should time out if it takes too long
    try:
        with timeout(config.configure_timeout):
            # Get the dynamically allocated port from the SSH process
            # This is received on stdout, but we have configured the process to send
            # stderr to stdout
            allocated_port = get_allocated_port(ssh_proc.stdout)
            # Build the config object
            tunnel_config = dict(
                allocated_port = allocated_port,
                backend_protocol = config.backend_protocol,
            )
            if config.read_timeout:
                tunnel_config.update(read_timeout = config.read_timeout)
            if config.skip_auth:
                tunnel_config.update(skip_auth = True)
            else:
                tunnel_config.update(auth_type = config.auth_type.value)
                if config.auth_type == AuthType.OIDC:
                    tunnel_config.update(
                        auth_oidc_issuer = config.auth_oidc_issuer,
                        auth_oidc_client_id = config.auth_oidc_client_id,
                        auth_oidc_client_secret = config.auth_oidc_client_secret
                    )
                elif config.auth_external_params:
                    tunnel_config.update(auth_external_params = config.auth_external_params)
            if config.tls_cert_file:
                tunnel_config.update(
                    tls_cert = config.tls_cert_data,
                    tls_key = config.tls_key_data
                )
            if config.tls_client_ca_file:
                tunnel_config.update(tls_client_ca = config.tls_client_ca_data)
            if config.liveness_path:
                tunnel_config.update(
                    liveness_path = config.liveness_path,
                    liveness_period = config.liveness_period,
                    liveness_failures = config.liveness_failures
                )
            # The server will ask for the config when it is ready
            wait_for_marker(ssh_proc.stdout, "SEND_CONFIGURATION")
            # Dump the configuration as JSON and encode it as base64 with line breaks
            config = base64.encodebytes(json.dumps(tunnel_config).encode()).decode()
            # Send each line to the SSH process
            for line in config.splitlines():
                print(line, file = ssh_proc.stdin)
            # We need to send a newline to trigger the read on the server
            print("", file = ssh_proc.stdin)
            # Indicate that we have sent all the configuration that we will send
            print("END_CONFIGURATION", file = ssh_proc.stdin)
            ssh_proc.stdin.flush()
            # Wait for the server to confirm that it received the config
            wait_for_marker(ssh_proc.stdout, "RECEIVED_CONFIGURATION")
            logger.info("[CLIENT] Tunnel configured successfully")
    except TimeoutError:
        logger.error("[CLIENT] Timed out negotiating tunnel configuration")
        # Terminate the SSH process before exiting
        ssh_proc.terminate()
        sys.exit(1)


@contextlib.contextmanager
def ssh_identity(config):
    """
    Context manager that makes a temporary file to contain the SSH identity, populates it
    (either using the given private key or by generating one) and yields the path.
    """
    # In order to support Windows, we cannot use the NamedTemporaryFile context manager
    # to wrap all the logic because the file cannot be opened by the SSH process
    # https://bugs.python.org/issue14243
    # Instead, we must clean the file up ourselves
    ssh_private_key_file_name = None
    with tempfile.NamedTemporaryFile(delete = False) as ssh_private_key_file:
        ssh_private_key_file_name = ssh_private_key_file.name
        logger.info("[CLIENT] Writing SSH private key data to temporary file")
        # If the private key data was given, use it (it is base64-encoded)
        ssh_private_key_file.write(base64.b64decode(config.ssh_private_key_data))
    # Make sure the key file has the correct permissions
    os.chmod(ssh_private_key_file_name, 0o600)
    try:
        yield ssh_private_key_file_name
    finally:
        # Try our best to clean up the file
        try:
            os.remove(ssh_private_key_file_name)
        except OSError:
            pass


def create(config):
    """
    Creates a tunnel with the given configuration.
    """
    # If running as root and another user has been specified, switch to that user
    if config.run_as_user:
        if os.getuid() == 0:
            logger.info("[CLIENT] Switching to uid '%d'", config.run_as_user)
            os.setuid(config.run_as_user)
        else:
            logger.warn("[CLIENT] Cannot switch user - not running as root")

    with ssh_identity(config) as ssh_identity_path:
        # Derive the SSH command to use from the configuration
        ssh_command = [
            config.ssh_executable,
            # Force a TTY so that we can send data over stdin
            "-tt",
            # Exit immediately if the port forwarding fails
            "-o",
            "ExitOnForwardFailure=yes",
            # Ignore host keys (for now)
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            # Use the generated authorized key to authenticate
            "-o",
            "IdentitiesOnly=yes",
            "-i",
            ssh_identity_path,
            # Use the configured server alive interval
            "-o",
            f"ServerAliveInterval={config.server_alive_period}",
            "-o",
            f"ServerAliveCountMax={config.server_alive_failures}",
            # Use a dynamically allocated port
            "-R",
            f"0:{config.forward_to_host}:{config.forward_to_port}",
            # Configure the Zenith server
            "-p",
            str(config.server_port),
            f"zenith@{config.server_address}",
        ]

        logger.info("[CLIENT] Spawning SSH process")
        logger.debug("[CLIENT] SSH command - %s", " ".join(ssh_command))

        # Open the SSH process
        ssh_proc = subprocess.Popen(
            ssh_command,
            text = True,
            stdin = subprocess.PIPE,
            stdout = subprocess.PIPE,
            # Send stderr to the same handler as stdout
            stderr = subprocess.STDOUT
        )

        logger.info("[CLIENT] Negotiating tunnel configuration")

        configure_tunnel(ssh_proc, config)

        # Forward stdout (which contains stderr) until the SSH process exits
        for line in ssh_proc.stdout:
            print(line.rstrip())

        # Belt and braces to make sure the process has definitely terminated
        ssh_proc.wait()

        if ssh_proc.returncode == 0:
            logger.info("[CLIENT] SSH process exited cleanly")
        else:
            logger.error(
                "[CLIENT] SSH process exited with non-zero exit code (%d)",
                ssh_proc.returncode
            )

        # Exit with the returncode from the SSH command
        sys.exit(ssh_proc.returncode)
