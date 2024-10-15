import base64
import socket
import typing
import warnings

from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from pydantic import (
    BaseModel,
    TypeAdapter,
    Field,
    AfterValidator,
    AnyHttpUrl as PyAnyHttpUrl,
    conint,
    constr,
    field_validator,
    ValidationInfo
)

import requests


#: Type for an OIDC allowed group
AllowedGroup = constr(pattern =r"^[a-zA-Z0-9_/-]+$")

#: Type for a key in the authentication parameters
#: This will become a header name, so limit to lowercase alpha-numeric + -
#: Although HTTP specifies no size limit, we do for readability
AuthParamsKey = constr(pattern =r"^[a-z][a-z0-9-]*?[a-z0-9]$", max_length = 50)
#: Type for a value in the authentication parameters
#: Must fit in an HTTP header, so limited to 1024 unicode characters (4KB)
AuthParamsValue = constr(max_length = 1024)

#: Type for an RFC3986 compliant URL path component
UrlPath = constr(pattern =r"/[a-zA-Z0-9._~!$&'()*+,;=:@%/-]*", min_length = 1)

#: Type for a string that validates as a URL
AnyHttpUrl = typing.Annotated[
    str,
    AfterValidator(lambda v: str(TypeAdapter(PyAnyHttpUrl).validate_python(v)))
]


class ClientConfig(BaseModel, extra = "forbid"):
    """
    Object for validating the client configuration.
    """
    #: The port for the service (the tunnel port)
    allocated_port: int
    #: The backend protocol
    backend_protocol: typing.Literal["http", "https", "ssh"] = "http"
    #: The read timeout for the service (in seconds)
    read_timeout: typing.Optional[conint(gt = 0)] = None
    #: Indicates whether the service is internal, i.e. without ingress
    internal: bool = Field(False, validate_default = True)
    #: Indicates whether the proxy authentication should be skipped
    skip_auth: bool = Field(False, validate_default = True)
    #: The URL of the OIDC issuer to use
    auth_oidc_issuer: typing.Optional[AnyHttpUrl] = None
    #: The OIDC client ID to use
    auth_oidc_client_id: typing.Optional[constr(min_length = 1)] = Field(
        None,
        validate_default = True
    )
    #: The OIDC client secret to use
    auth_oidc_client_secret: typing.Optional[constr(min_length = 1)] = Field(
        None,
        validate_default = True
    )
    #: The OIDC groups that are allowed access to the the service
    #: The user must have at least one of these groups in their groups claim
    auth_oidc_allowed_groups: typing.List[AllowedGroup] = Field(default_factory = list)
    #: Parameters for the external authentication service (deprecated name)
    auth_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(default_factory = dict)
    #: Parameters for the external authentication service
    auth_external_params: typing.Dict[AuthParamsKey, AuthParamsValue] = Field(
        default_factory = dict,
        validate_default = True
    )
    #: Base64-encoded TLS certificate to use
    tls_cert: typing.Optional[str] = None
    #: Base64-encoded TLS private key to use (corresponds to TLS cert)
    tls_key: typing.Optional[str] = Field(None, validate_default = True)
    #: Base64-encoded CA for validating TLS client certificates, if required
    tls_client_ca: typing.Optional[str] = None
    #: An optional liveness path
    liveness_path: typing.Optional[UrlPath] = None
    #: The period for liveness checks in seconds
    liveness_period: conint(gt = 0) = 10
    #: The number of liveness checks that can fail before the tunnel is considered unhealthy
    liveness_failures: conint(gt = 0) = 3

    @field_validator("allocated_port")
    @classmethod
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

    @field_validator("internal")
    @classmethod
    def validate_internal(cls, v, info: ValidationInfo):
        """
        Validates that internal is set when required.
        """
        # If the SSH protocol is specified, the tunnel must be internal
        backend_protocol = info.data.get("backend_protocol", "http")
        if not v and backend_protocol == "ssh":
            warnings.warn("SSH protocol is only supported for internal tunnels")
            return True
        return v

    @field_validator("skip_auth")
    @classmethod
    def validate_skip_auth(cls, v, info: ValidationInfo):
        """
        Validates that auth is skipped when it is not available.
        """
        # Auth is always skipped for internal tunnels, as it is applied at the ingress
        if not v and info.data.get("internal", False):
            warnings.warn("auth is always skipped for internal tunnels")
            return True
        return v

    @field_validator("auth_external_params", mode = "before")
    @classmethod
    def validate_auth_external_params(cls, v, info: ValidationInfo):
        """
        Makes sure that the old name for external auth params is respected.
        """
        return v or info.data.get("auth_params", {})

    @field_validator("auth_oidc_issuer")
    @classmethod
    def validate_auth_oidc_issuer(cls, v):
        """
        Validates that the OIDC issuer supports discovery.
        """
        issuer_url = v.rstrip("/")
        response = requests.get(f"{issuer_url}/.well-known/openid-configuration")
        if 200 <= response.status_code < 300:
            return v
        else:
            raise ValueError("OIDC issuer does not support discovery")

    @field_validator("auth_oidc_client_id")
    @classmethod
    def validate_auth_oidc_client_id(cls, v, info: ValidationInfo):
        """
        Validates that an OIDC client id is given when an OIDC issuer is present.
        """
        skip_auth = info.data.get("skip_auth", False)
        oidc_issuer = info.data.get("auth_oidc_issuer")
        if not skip_auth and oidc_issuer and not v:
            raise ValueError("required for OIDC authentication")
        return v

    @field_validator("auth_oidc_client_secret")
    @classmethod
    def validate_auth_oidc_client_secret(cls, v, info: ValidationInfo):
        """
        Validates that a client secret is given when a client ID is present.
        """
        skip_auth = info.data.get("skip_auth", False)
        oidc_issuer = info.data.get("auth_oidc_issuer")
        if not skip_auth and oidc_issuer and not v:
            raise ValueError("required for OIDC authentication")
        return v

    @field_validator("tls_cert")
    @classmethod
    def validate_tls_cert(cls, v):
        """
        Validate the given value decoding it and trying to load it as a
        PEM-encoded X509 certificate.
        """
        _ = load_pem_x509_certificate(base64.b64decode(v))
        return v

    @field_validator("tls_key")
    @classmethod
    def validate_tls_key(cls, v, info: ValidationInfo):
        """
        Validate the given value by decoding it and trying to load it as a
        PEM-encoded private key.
        """
        tls_cert = info.data.get("tls_cert")
        if tls_cert and not v:
            raise ValueError("required if TLS cert is specified")
        if v:
            _ = load_pem_private_key(base64.b64decode(v), None)
        return v

    @field_validator("tls_client_ca")
    @classmethod
    def validate_tls_client_ca(cls, v):
        """
        Validate the given value by decoding it and trying to load it as a
        PEM-encoded X509 certificate.
        """
        _ = load_pem_x509_certificate(base64.b64decode(v))
        return v

    def as_sync_config(self) -> typing.Dict[str, typing.Any]:
        """
        Returns the tunnel config object as understood by sync.
        """
        # Build the service metadata object
        config = { "backend-protocol": self.backend_protocol }
        if self.read_timeout:
            config["read-timeout"] = self.read_timeout
        config["internal"] = self.internal
        config["skip-auth"] = self.skip_auth
        if not self.skip_auth:
            if self.auth_oidc_issuer:
                config.update({
                    "auth-oidc-issuer": self.auth_oidc_issuer,
                    "auth-oidc-client-id": self.auth_oidc_client_id,
                    "auth-oidc-client-secret": self.auth_oidc_client_secret,
                    "auth-oidc-allowed-groups": self.auth_oidc_allowed_groups,
                })
            elif self.auth_external_params:
                config["auth-external-params"] = self.auth_external_params
        if self.tls_cert:
            config.update({
                "tls-cert": self.tls_cert,
                "tls-key": self.tls_key,
            })
        if self.tls_client_ca:
            config["tls-client-ca"] = self.tls_client_ca
        return config
