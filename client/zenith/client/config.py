import base64
import pathlib
import typing

from pydantic import Field, FilePath, AnyHttpUrl, conint, constr, validator

from configomatic import Configuration, LoggingConfiguration


#: Constraint for Zenith auth params keys and values
AuthParamsKey = constr(regex = r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 50)
AuthParamsValue = constr(max_length = 1024)

#: Type for an RFC3986 compliant URL path component
UrlPath = constr(regex = r"/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]*", min_length = 1)


def base64_encoded_content(path):
    """
    Returns the base64-encoded content of the file at the given path as a string.
    """
    with path.open("rb") as fh:
        return base64.b64encode(fh.read()).decode()


class InitConfig(Configuration):
    """
    Configuration model for the init command.
    """
    class Config:
        default_path = "/etc/zenith/client.yaml"
        path_env_var = "ZENITH_CLIENT_CONFIG"
        env_prefix = "ZENITH_CLIENT"

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The ssh-keygen executable to use
    ssh_keygen_executable: str = "ssh-keygen"
    #: The path of the SSH identity to use
    #: Either the identity already exists or a new keypair is generated at the specified location
    ssh_identity_path: pathlib.Path
    #: The Zenith registrar URL to use to associate the public key
    registrar_url: AnyHttpUrl
    #: The Zenith registrar token to use to associate the public key
    token: constr(min_length = 1)
    #: Indicates whether to verify the TLS certificate of the registrar
    verify_ssl: bool = True


class ConnectConfig(Configuration):
    """
    Configuration model for the connect command.
    """
    class Config:
        default_path = "/etc/zenith/client.yaml"
        path_env_var = "ZENITH_CLIENT_CONFIG"
        env_prefix = "ZENITH_CLIENT"

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The SSH executable to use
    ssh_executable: str = "ssh"
    #: The user to run as, once configuration has been read
    #: Only applies when the script is executing as root
    run_as_user: typing.Optional[conint(gt = 0)] = None
    #: The path to an SSH identity file to use
    ssh_identity_path: typing.Optional[FilePath] = None
    #: The SSH private key to use
    ssh_private_key_data: typing.Optional[str] = None
    #: The time to wait for a successful configuration before timing out
    configure_timeout: int = 10
    #: The address of the target Zenith server
    server_address: str
    #: The port of the target Zenith server
    server_port: int = 22
    #: The address to forward tunnel traffic to
    forward_to_host: str = "localhost"
    #: The port to forward tunnel traffic to
    forward_to_port: int = 8000
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https"] = "http"
    #: An optional liveness path for the upstream service
    liveness_path: typing.Optional[UrlPath] = None
    #: The period for upstream liveness checks in seconds
    liveness_period: conint(gt = 0) = 10
    #: The number of liveness checks that can fail before the tunnel is considered unhealthy
    liveness_failures: conint(gt = 0) = 3
    #: The read timeout for the service
    read_timeout: typing.Optional[conint(gt = 0)] = None
    #: Indicates whether the proxy authentication should be skipped
    skip_auth: bool = False
    #: Parameters for the proxy authentication service
    auth_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
    #: Path to a file containing a TLS certificate chain to use
    tls_cert_file: typing.Optional[FilePath] = None
    #: Base64-encoded TLS certificate to use
    tls_cert_data: typing.Optional[str] = None
    #: Path to a file containing a TLS certificate key to use
    tls_key_file: typing.Optional[FilePath] = None
    #: Base64-encoded TLS certificate key to use
    tls_key_data: typing.Optional[str] = None
    #: Path to a file containing a CA to use to validate TLS client certificates
    tls_client_ca_file: typing.Optional[FilePath] = None
    #: Base64-encoded CA to use to validate TLS client certificates
    tls_client_ca_data: typing.Optional[str] = None

    @validator("auth_params", pre = True)
    def pre_validate_auth_params(cls, value):
        """
        Applies pre-validation to the auth params.
        """
        # In order to properly support keys coming from environment variables, we need
        # to replace underscores with hyphens in the keys
        if isinstance(value, dict):
            return { k.replace("_", "-"): v for k, v in value.items() }
        else:
            return value

    @validator("ssh_private_key_data", always = True)
    def validate_ssh_private_key_data(cls, v, *, values):
        """
        Validates the SSH private key data.
        """
        if v:
            return v
        ssh_identity_path = values.get("ssh_identity_path")
        if ssh_identity_path:
            return base64_encoded_content(ssh_identity_path)
        else:
            raise ValueError("No SSH private key specified.")

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
