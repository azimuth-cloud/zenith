import re

from pydantic import Field

from zenith.common.config import Configuration, Section


class ConsulConfig(Section):
    """
    Model for the Consul configuration section.
    """
    #: The URL to use to access Consul
    url: str = "http://127.0.0.1:8500"
    #: The timeout to use with Consul blocking queries
    blocking_query_timeout: int = 300
    #: The tag to use to filter out Zenith services
    service_tag: str = "zenith-service"


class DNSLabel(str):
    """
    Custom datatype that validates a DNS label.

    DNS labels must contain only alphanumeric characters and hyphens, have less than 63
    characters and not start or end with a hyphen.
    """
    REGEX = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]*?[a-zA-Z0-9]$")

    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        """
        Validates the given value as a DNS label.
        """
        if not isinstance(v, str):
            raise TypeError("must be a string")
        if len(v) > 63:
            raise ValueError("must have at most 63 characters")
        if cls.REGEX.fullmatch(v) is None:
            raise ValueError(f"'{v} is not a valid DNS label")
        return cls(v)   
    

class DomainName(str):
    """
    Custom datatype that validates a domain name.
    """
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        """
        Validates the given value as a DNS name
        """
        if not isinstance(v, str):
            raise TypeError("must be a string")
        # A valid domain should have two or more valid DNS labels separated by dots
        dns_labels = v.split(".")
        if len(dns_labels) < 2:
            raise ValueError("domain name must contain at least two DNS labels")
        return cls(".".join(DNSLabel.validate(dns_label) for dns_label in dns_labels))


class IngressConfig(Section):
    """
    Model for the ingress configuration section.
    """
    #: Base domain for the proxied services
    base_domain: DomainName


class KubernetesConfig(Section):
    """
    Model for the Kubernetes configuration section.
    """
    #: The namespace to create Zenith service resources in
    namespace: str = "zenith-services"
    #: The label used to indicate a managed resource
    created_by_label: str = "app.kubernetes.io/created-by"
    #: The label used to indicate the corresponding Zenith service for a resource
    service_name_label: str = "zenith.stackhpc.com/service-name"
    #: The ingress configuration
    ingress: IngressConfig


class SyncConfig(Configuration):
    """
    Configuration model for the zenith-sync package.
    """
    class Config:
        default_path = '/etc/zenith/sync.yaml'
        path_env_var = 'ZENITH_SYNC_CONFIG'
        env_prefix = 'ZENITH_SYNC'

    #: The Consul configuration
    consul: ConsulConfig = Field(default_factory = ConsulConfig)
    #: The Kubernetes configuration
    kubernetes: KubernetesConfig = Field(default_factory = KubernetesConfig)
