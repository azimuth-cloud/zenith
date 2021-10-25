import os
import random
import subprocess
import string
import tempfile
import typing

from pydantic import Field, FilePath, constr, validator

from configomatic import Configuration, LoggingConfiguration


#: Constraint for a Zenith subdomain
Subdomain = constr(regex = r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 63)


def default_subdomain():
    """
    Returns a random subdomain consisting of 32 alphanumeric characters.
    """
    # Domains must start with a letter
    chars = [random.choice(string.ascii_lowercase)]
    chars.extend(random.choices(string.ascii_lowercase + string.digits, k = 31))
    return "".join(chars)


def default_ssh_identity_path():
    """
    Generates a temporary SSH identity and returns the path.
    """
    key_directory = tempfile.mkdtemp()
    key_file = os.path.join(key_directory, "id_rsa")
    # Use a 2048-bit RSA key as it represents an acceptable compromise between speed
    # of generation and security, especially for a disposible key
    subprocess.check_call([
        "ssh-keygen",
        "-t",
        "rsa",
        "-b",
        "2048",
        "-N",
        "",
        "-C",
        "zenith-key",
        "-f",
        key_file
    ])
    return key_file


class ClientConfig(Configuration):
    """
    Configuration model for the zenith-client package.
    """
    class Config:
        default_path = '/etc/zenith/client.yaml'
        path_env_var = 'ZENITH_CLIENT_CONFIG'
        env_prefix = 'ZENITH_CLIENT'

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The SSH executable to use
    ssh_executable: str = "ssh"
    #: Path to the SSH identity to use
    #: If not given, a temporary SSH key is created
    ssh_identity_path: FilePath = Field(default_factory = default_ssh_identity_path)
    #: The time to wait for a successful configuration before timing out
    configure_timeout: int = 5
    #: The address of the target Zenith server
    server_address: str
    #: The port of the target Zenith server
    server_port: int = 22
    #: The address to forward tunnel traffic to
    forward_to_host: str = "localhost"
    #: The port to forward tunnel traffic to
    forward_to_port: int = 8000
    #: The subdomain to request
    #: If not given, a random subdomain is used
    #: Subdomains must be at most 63 characters long, can only contain alphanumeric characters
    #: and hyphens, and cannot start or end with a hyphen
    #: In addition, Zenith subdomains must start with a letter and be lower case
    subdomain: Subdomain = Field(default_factory = default_subdomain)
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https"] = "http"
