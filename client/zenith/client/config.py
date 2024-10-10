import base64
import pathlib
import typing

from pydantic import (
    TypeAdapter,
    Field,
    FilePath,
    AnyHttpUrl as PyAnyHttpUrl,
    conint,
    constr,
    field_validator,
    ValidationInfo
)
from pydantic.functional_validators import AfterValidator

from configomatic import Configuration, LoggingConfiguration


#: Constraint for Zenith auth params keys and values
AuthParamsKey = constr(pattern =r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 50)
AuthParamsValue = constr(max_length = 1024)

#: Type for an RFC3986 compliant URL path component
UrlPath = constr(pattern =r"/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]*", min_length = 1)

#: Type for a string that validates as a URL
AnyHttpUrl = typing.Annotated[
    str,
    AfterValidator(lambda v: str(TypeAdapter(PyAnyHttpUrl).validate_python(v)))
]


def base64_encoded_content(path):
    """
    Returns the base64-encoded content of the file at the given path as a string.
    """
    with path.open("rb") as fh:
        return base64.b64encode(fh.read()).decode()


def strip_trailing_slash(v: str) -> str:
    """
    Strips trailing slashes from the given string.
    """
    return v.rstrip("/")


class InitConfig(
    Configuration,
    default_path = "/etc/zenith/client.yaml",
    path_env_var = "ZENITH_CLIENT_CONFIG",
    env_prefix = "ZENITH_CLIENT"
):
    """
    Configuration model for the init command.
    """
    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The ssh-keygen executable to use
    ssh_keygen_executable: str = "ssh-keygen"
    #: The path of the SSH identity to use
    #: Either the identity already exists or a new keypair is generated at the specified location
    ssh_identity_path: pathlib.Path
    #: The Zenith registrar URL to use to associate the public key
    registrar_url: typing.Annotated[AnyHttpUrl, AfterValidator(strip_trailing_slash)]
    #: The Zenith registrar token to use to associate the public key
    token: constr(min_length = 1)
    #: Indicates whether to verify the TLS certificate of the registrar
    verify_ssl: bool = True


class ConnectConfig(
    Configuration,
    default_path = "/etc/zenith/client.yaml",
    path_env_var = "ZENITH_CLIENT_CONFIG",
    env_prefix = "ZENITH_CLIENT"
):
    """
    Configuration model for the connect command.
    """
    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: Indicates whether we are in debug mode
    debug: bool = False

    #: The SSH executable to use
    ssh_executable: str = "ssh"
    #: The user to run as, once configuration has been read
    #: Only applies when the script is executing as root
    run_as_user: typing.Optional[conint(gt = 0)] = None
    #: The path to an SSH identity file to use
    ssh_identity_path: typing.Optional[FilePath] = None
    #: The SSH private key to use
    ssh_private_key_data: typing.Optional[str] = Field(None, validate_default = True)
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
    #: The period after which a server alive message will be sent if no data is received
    server_alive_period: conint(gt = 0) = 10
    #: The number of server alive messages that can fail before the tunnel is terminated
    server_alive_failures: conint(gt = 0) = 3
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https", "ssh"] = "http"
    #: An optional liveness path for the upstream service
    liveness_path: typing.Optional[UrlPath] = None
    #: The period for upstream liveness checks in seconds
    liveness_period: conint(gt = 0) = 10
    #: The number of liveness checks that can fail before the tunnel is considered unhealthy
    liveness_failures: conint(gt = 0) = 3
    #: The read timeout for the service
    read_timeout: typing.Optional[conint(gt = 0)] = None
    #: Indicates whether the service should be internal, i.e. no ingress
    internal: bool = False
    #: Indicates whether the proxy authentication should be skipped
    skip_auth: bool = False
    #: The URL of the OIDC issuer to use (only used when auth_type == "oidc")
    auth_oidc_issuer: typing.Optional[AnyHttpUrl] = None
    #: The OIDC client ID, if known
    auth_oidc_client_id: typing.Optional[constr(min_length = 1)] = None
    #: The OIDC client secret, required if client ID is given
    auth_oidc_client_secret: typing.Optional[constr(min_length = 1)] = None
    #: The OIDC groups that are allowed access to the the service
    #: The user must have at least one of these groups in their groups claim
    auth_oidc_allowed_groups: typing.List[constr(pattern =r"^[a-zA-Z0-9_/-]+$")] = Field(default_factory = list)
    #: Parameters for the proxy authentication service
    auth_external_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
    #: Path to a file containing a TLS certificate chain to use
    tls_cert_file: typing.Optional[FilePath] = None
    #: Base64-encoded TLS certificate to use
    tls_cert_data: typing.Optional[str] = Field(None, validate_default = True)
    #: Path to a file containing a TLS certificate key to use
    tls_key_file: typing.Optional[FilePath] = None
    #: Base64-encoded TLS certificate key to use
    tls_key_data: typing.Optional[str] = Field(None, validate_default = True)
    #: Path to a file containing a CA to use to validate TLS client certificates
    tls_client_ca_file: typing.Optional[FilePath] = None
    #: Base64-encoded CA to use to validate TLS client certificates
    tls_client_ca_data: typing.Optional[str] = Field(None, validate_default = True)

    @field_validator("auth_oidc_allowed_groups", mode = "before")
    @classmethod
    def pre_validate_auth_oidc_allowed_groups(cls, v):
        """
        Applies pre-validation to the allowed groups.
        """
        # In order to properly support allowed groups from an environment variable,
        # we also support using a comma-separated string
        if isinstance(v, str):
            return v.split(",")
        else:
            return v

    @field_validator("auth_external_params", mode = "before")
    @classmethod
    def pre_validate_auth_external_params(cls, v):
        """
        Applies pre-validation to the auth params.
        """
        # In order to properly support keys coming from environment variables, we need
        # to replace underscores with hyphens in the keys
        if isinstance(v, dict):
            return { k.replace("_", "-"): v for k, v in v.items() }
        else:
            return v

    @field_validator("ssh_private_key_data")
    @classmethod
    def validate_ssh_private_key_data(cls, v, info: ValidationInfo):
        """
        Validates the SSH private key data.
        """
        if v:
            return v
        ssh_identity_path = info.data.get("ssh_identity_path")
        if ssh_identity_path:
            return base64_encoded_content(ssh_identity_path)
        else:
            raise ValueError("No SSH private key specified.")

    @field_validator("tls_cert_data")
    @classmethod
    def validate_tls_cert_data(cls, v, info: ValidationInfo):
        """
        Validates the TLS cert data.
        """
        if v:
            return v
        tls_cert_file = info.data.get("tls_cert_file")
        if tls_cert_file:
            return base64_encoded_content(tls_cert_file)
        else:
            return None

    @field_validator("tls_key_data")
    @classmethod
    def validate_tls_key_data(cls, v, info: ValidationInfo):
        """
        Validates the TLS private key data.
        """
        if v:
            return v
        tls_key_file = info.data.get("tls_key_file")
        if tls_key_file:
            return base64_encoded_content(tls_key_file)
        if info.data.get("tls_cert_data"):
            raise ValueError("TLS key is required if TLS cert is specified")
        else:
            return None

    @field_validator("tls_client_ca_data")
    @classmethod
    def validate_tls_client_ca_data(cls, v, info: ValidationInfo):
        """
        Validates the TLS client CA data.
        """
        if v:
            return v
        tls_client_ca_file = info.data.get("tls_client_ca_file")
        if tls_client_ca_file:
            return base64_encoded_content(tls_client_ca_file)
        else:
            return None
