import re
import typing as t

from pydantic import Field, AnyHttpUrl, conint, constr

from configomatic import Configuration, Section, LoggingConfiguration


class ConsulConfig(Section):
    """
    Model for the Consul configuration section.
    """
    #: The address of the Consul server
    address: str = "127.0.0.1"
    #: The port of the Consul server
    port: int = 8500
    #: The timeout to use with Consul blocking queries
    blocking_query_timeout: int = 300
    #: The tag to use to filter out Zenith services
    service_tag: str = "zenith-service"
    #: The prefix to use when looking for tunnel configurations in the KV store
    config_key_prefix: str = "zenith/services"

    @property
    def url(self):
        """
        The URL to use to access Consul.
        """
        return f"http://{self.address}:{self.port}"


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


class OIDCConfig(Section):
    """
    Model for the ingress OIDC configuration section.
    """
    #: The chart repository containing the proxy chart
    oauth2_proxy_chart_repo: AnyHttpUrl = "https://oauth2-proxy.github.io/manifests"
    #: The name of the proxy chart
    oauth2_proxy_chart_name: constr(min_length = 1) = "oauth2-proxy"
    #: The version of the proxy chart
    oauth2_proxy_chart_version: constr(min_length = 1) = "6.5.0"
    #: Default values for the proxy release
    oauth2_proxy_default_values: t.Dict[str, t.Any] = Field(default_factory = dict)


class ExternalAuthConfig(Section):
    """
    Model for the ingress external auth configuration section.
    """
    #: The external authentication URL
    #: If not supplied, no external auth is applied
    #: This URL is called as a subrequest, and so will receive the original request body
    #: and headers. If it returns a response with a 2xx status code, the request proceeds
    #: to the upstream. If it returns a 401 or a 403, the access is denied.
    url: t.Optional[AnyHttpUrl] = None
    #: The URL to redirect to on an authentication error
    signin_url: t.Optional[AnyHttpUrl] = None
    #: The URL parameter to contain the original URL when redirecting to the signin URL
    next_url_param: str = "next"
    #: Dictionary of headers to set for authentication requests
    #: These will override headers from the incoming request, which would otherwise be forwarded
    #: In particular, you may need to override the accepts header to suit the content types served
    #: by the external authentication service
    request_headers: t.Dict[str, str] = Field(default_factory = dict)
    #: List of headers from the authentication response to add to the upstream request
    response_headers: t.List[str] = Field(default_factory = list)
    #: The additional prefix to use when passing authentication parameters to the auth service
    param_header_prefix: str = "x-"


class TLSConfig(Section):
    """
    Model for the ingress TLS configuration section.
    """
    #: Indicates whether TLS should be enabled
    enabled: bool = True
    #: The name of a secret containing a wildcard certificate
    secret_name: t.Optional[str] = None
    #: Annotations to add to ingress resources that are TLS-specific
    annotations: t.Dict[str, str] = Field(default_factory = dict)


class IngressConfig(Section):
    """
    Model for the ingress configuration section.
    """
    #: Base domain for the proxied services
    base_domain: DomainName
    #: The ingress class to use when creating ingress resources
    class_name: str = "nginx"
    #: Annotations to add to all ingress resources
    annotations: t.Dict[str, str] = Field(default_factory = dict)
    #: The TLS configuration
    tls: TLSConfig = Field(default_factory = TLSConfig)
    #: The OIDC configuration
    oidc: OIDCConfig = Field(default_factory = OIDCConfig)
    #: The external auth configuration
    external_auth: ExternalAuthConfig = Field(default_factory = ExternalAuthConfig)


class HelmClientConfiguration(Section):
    """
    Configuration for the Helm client.
    """
    #: The default timeout to use with Helm releases
    #: Can be an integer number of seconds or a duration string like 5m, 5h
    default_timeout: t.Union[int, constr(min_length = 1)] = "5m"
    #: The executable to use
    #: By default, we assume Helm is on the PATH
    executable: constr(min_length = 1) = "helm"
    #: The maximum number of revisions to retain in the history of releases
    history_max_revisions: int = 10
    #: Indicates whether to verify TLS when pulling charts
    insecure_skip_tls_verify: bool = False
    #: The directory to use for unpacking charts
    #: By default, the system temporary directory is used
    unpack_directory: t.Optional[str] = None


class KubernetesConfig(Section):
    """
    Model for the Kubernetes configuration section.
    """
    #: The DNS domain for cluster services
    cluster_services_domain: str = "svc.cluster.local"
    #: The namespace that the sync component is running in
    self_namespace: str
    #: The namespace to create Zenith service resources in
    target_namespace: str = "zenith-services"
    #: The label used to indicate a managed resource
    created_by_label: str = "app.kubernetes.io/created-by"
    #: The label used to indicate the corresponding Zenith service for a resource
    service_name_label: str = "zenith.stackhpc.com/service-name"
    #: The annotation used to record that a secret is a mirror of another secret
    tls_mirror_annotation: str = "zenith.stackhpc.com/mirrors"
    #: The number of times that a failed reconciliation will be retried before giving up
    reconciliation_retries: conint(gt = 0) = 3
    #: The ingress configuration
    ingress: IngressConfig
    #: The Helm client configuration
    helm_client: HelmClientConfiguration = Field(default_factory = HelmClientConfiguration)


class SyncConfig(Configuration):
    """
    Configuration model for the zenith-sync package.
    """
    class Config:
        default_path = '/etc/zenith/sync.yaml'
        path_env_var = 'ZENITH_SYNC_CONFIG'
        env_prefix = 'ZENITH_SYNC'

    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The Consul configuration
    consul: ConsulConfig = Field(default_factory = ConsulConfig)
    #: The Kubernetes configuration
    kubernetes: KubernetesConfig = Field(default_factory = KubernetesConfig)
