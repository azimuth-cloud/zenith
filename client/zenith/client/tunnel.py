import base64
import contextlib
import json
import logging
import re
import signal
import subprocess
import sys


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
    """
    previous = signal.signal(signal.SIGALRM, raise_timeout_error)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def base64_encoded_content(path):
    """
    Returns the base64-encoded content of the file at the given path as a string.
    """
    with path.open("rb") as fh:
        return base64.b64encode(fh.read()).decode()


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
                subdomain = config.subdomain,
                backend_protocol = config.backend_protocol,
            )
            if config.read_timeout:
                tunnel_config.update(read_timeout = config.read_timeout)
            if config.tls_cert_file:
                tunnel_config["tls_cert"] = base64_encoded_content(config.tls_cert_file)
                tunnel_config["tls_key"] = base64_encoded_content(config.tls_key_file)
            if config.tls_client_ca_file:
                tunnel_config["tls_client_ca"] = base64_encoded_content(config.tls_client_ca_file)
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


def create(config):
    """
    Creates a tunnel with the given configuration.
    """
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
        config.ssh_identity_path,
        # Use a dynamically allocated port
        "-R",
        f"0:{config.forward_to_host}:{config.forward_to_port}",
        # Configure the Zenith server
        "-p",
        str(config.server_port),
        f"zenith@{config.server_address}",
    ]

    logging.info("[CLIENT] Spawning SSH process")
    logging.debug("[CLIENT] SSH command - %s", " ".join(ssh_command))

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
