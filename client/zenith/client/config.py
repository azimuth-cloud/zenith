import base64
import random
import string
import typing

from pydantic import Field, FilePath, conint, constr, validator

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


def base64_encoded_content(path):
    """
    Returns the base64-encoded content of the file at the given path as a string.
    """
    with path.open("rb") as fh:
        return base64.b64encode(fh.read()).decode()


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
    #: The user to run as, once configuration has been read
    #: Only applies when the script is executing as root
    run_as_user: typing.Optional[conint(gt = 0)] = Field(
        None,
        description = "UID to switch to after reading configuration (only used when executed as root)."
    )
    #: The SSH identity file to use
    #: If not given, a temporary SSH key is created
    ssh_identity_file: FilePath = Field(
        None,
        description = "The SSH identity file to use. If not given, a temporary identity is generated."
    )
    #: The SSH private key to use
    #: If not given, a temporary SSH key is created
    ssh_private_key_data: FilePath = Field(
        None,
        description = "Base64-encoded SSH private key to use. If not given, a temporary identity is generated."
    )
    #: The time to wait for a successful configuration before timing out
    configure_timeout: int = Field(
        10,
        description = "Time to wait for a successful configuration before timing out."
    )
    #: The address of the target Zenith server
    server_address: str = Field(
        ...,
        description = "The address of the target Zenith server."
    )
    #: The port of the target Zenith server
    server_port: int = Field(
        22,
        description = "The port of the target Zenith server."
    )
    #: The address to forward tunnel traffic to
    forward_to_host: str = Field(
        "localhost",
        description = "The address to forward tunnel traffic to."
    )
    #: The port to forward tunnel traffic to
    forward_to_port: int = Field(
        8000,
        description = "The port to forward tunnel traffic to."
    )
    #: The subdomain to request
    #: If not given, a random subdomain is used
    #: Subdomains must be at most 63 characters long, can only contain alphanumeric characters
    #: and hyphens, and cannot start or end with a hyphen
    #: In addition, Zenith subdomains must start with a letter and be lower case
    subdomain: Subdomain = Field(
        default_factory = default_subdomain,
        description = "The subdomain to request. If not given, a random subdomain is used."
    )
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https"] = Field(
        "http",
        description = "The backend protocol to use."
    )
    #: The read timeout for the service
    read_timeout: typing.Optional[conint(gt = 0)] = Field(
        None,
        description = "The read timeout to use."
    )
    #: Path to a file containing a TLS certificate chain to use
    tls_cert_file: typing.Optional[FilePath] = Field(
        None,
        description = "Path to a file containing a TLS certificate chain to use."
    )
    #: Base64-encoded TLS certificate to use
    tls_cert_data: typing.Optional[str] = Field(
        None,
        description = "Base64-encoded TLS certificate chain to use."
    )
    #: Path to a file containing a TLS certificate key to use
    tls_key_file: typing.Optional[FilePath] = Field(
        None,
        description = "Path to a file containing the TLS private key to use."
    )
    #: Base64-encoded TLS certificate key to use
    tls_key_data: typing.Optional[str] = Field(
        None,
        description = "Base64-encoded TLS private key data."
    )
    #: Path to a file containing a CA to use to validate TLS client certificates
    tls_client_ca_file: typing.Optional[FilePath] = Field(
        None,
        description = "Path to a file containing the CA for validating TLS client certificates."
    )
    #: Base64-encoded CA to use to validate TLS client certificates
    tls_client_ca_data: typing.Optional[str] = Field(
        None,
        description = "Base64-encoded CA for validating TLS client certificates."
    )

    @validator("ssh_private_key_data", always = True)
    def validate_ssh_private_key_data(cls, v, *, values):
        """
        Validates the SSH private key data.
        """
        if v:
            return v
        ssh_identity_file = values.get("ssh_identity_file")
        if ssh_identity_file:
            return base64_encoded_content(ssh_identity_file)
        else:
            return None

    @validator("tls_cert_data", always = True)
    def validate_tls_cert_data(cls, v, *, values):
        """
        Validates the TLS cert data.
        """
        if v:
            return v
        tls_cert_file = values.get("tls_cert_file")
        if tls_cert_file:
            return base64_encoded_content(tls_cert_file)
        else:
            return None

    @validator("tls_key_data", always = True)
    def validate_tls_key_data(cls, v, *, values):
        """
        Validates the TLS private key data.
        """
        if v:
            return v
        tls_key_file = values.get("tls_key_file")
        if tls_key_file:
            return base64_encoded_content(tls_key_file)
        if values.get("tls_cert_data"):
            raise ValueError("TLS key is required if TLS cert is specified")
        else:
            return None

    @validator("tls_client_ca_data", always = True)
    def validate_tls_client_ca_data(cls, v, *, values):
        """
        Validates the TLS client CA data.
        """
        if v:
            return v
        tls_client_ca_file = values.get("tls_client_ca_file")
        if tls_client_ca_file:
            return base64_encoded_content(tls_client_ca_file)
        else:
            return None
