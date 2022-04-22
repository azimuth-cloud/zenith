import typing as t

from pydantic import Field, AnyHttpUrl, FilePath, conint, constr, validator

from configomatic import Configuration as BaseConfiguration, Section, LoggingConfiguration


class WebhookConfiguration(Section):
    """
    Configuration for the internal webhook server.
    """
    #: The port to run the webhook server on
    port: conint(ge = 1000) = 8443
    #: Indicates whether kopf should manage the webhook configurations
    managed: bool = False
    #: The path to the TLS certificate to use
    certfile: t.Optional[FilePath] = None
    #: The path to the key for the TLS certificate
    keyfile: t.Optional[FilePath] = None
    #: The host for the webhook server (required for self-signed certificate generation)
    host: t.Optional[constr(min_length = 1)] = None

    @validator("certfile", always = True)
    def validate_certfile(cls, v, values, **kwargs):
        """
        Validate that certfile is specified when configs are not managed.
        """
        if "managed" in values and not values["managed"] and v is None:
            raise ValueError("required when webhook configurations are not managed")
        return v

    @validator("keyfile", always = True)
    def validate_keyfile(cls, v, values, **kwargs):
        """
        Validate that keyfile is specified when certfile is present.
        """
        if "certfile" in values and values["certfile"] is not None and v is None:
            raise ValueError("required when certfile is given")
        return v

    @validator("host", always = True)
    def validate_host(cls, v, values, **kwargs):
        """
        Validate that host is specified when there is no certificate specified.
        """
        if values.get("certfile") is None and v is None:
            raise ValueError("required when certfile is not given")
        return v


class Configuration(BaseConfiguration):
    """
    Top-level configuration model.
    """
    class Config:
        default_path = "/etc/zenith/operator.yaml"
        path_env_var = "ZENITH_OPERATOR_CONFIG"
        env_prefix = "ZENITH_OPERATOR"

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The API group of the cluster CRDs
    api_group: constr(min_length = 1) = "zenith.stackhpc.com"
    #: The secret type to use for secrets containing Zenith credentials
    credential_secret_type: constr(min_length = 1) = None

    #: The base domain used for cluster services
    cluster_service_domain: constr(regex = r"^[a-z0-9.-]+$") = "svc.cluster.local"

    #: The admin URL for the Zenith registrar
    registrar_admin_url: AnyHttpUrl
    #: The host for the Zenith SSHD service
    sshd_host: constr(min_length = 1)
    #: The port for the Zenith SSHD service
    sshd_port: conint(gt = 0) = 22

    # #: The webhook configuration
    webhook: WebhookConfiguration = Field(default_factory = WebhookConfiguration)

    @validator("credential_secret_type", pre = True, always = True)
    def default_credential_secret_type(cls, v, values, **kwargs):
        """
        Returns the default credential secret type based on the API group.
        """
        return v or f"{values['api_group']}/credential"


settings = Configuration()
