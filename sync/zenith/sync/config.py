import typing as t
import typing_extensions as te

from pydantic import (
    TypeAdapter,
    Field,
    AfterValidator,
    StringConstraints,
    AnyHttpUrl as PyAnyHttpUrl
)

from configomatic import Configuration, Section, LoggingConfiguration

from easysemver import SEMVER_VERSION_REGEX


#: Type for a string that validates as a SemVer version
SemVerVersion = t.Annotated[str, StringConstraints(pattern = SEMVER_VERSION_REGEX)]


#: Type for a non-empty string
NonEmptyString = t.Annotated[str, StringConstraints(min_length = 1)]


#: Type for a string that validates as a URL
AnyHttpUrl = t.Annotated[
    str,
    AfterValidator(lambda v: str(TypeAdapter(PyAnyHttpUrl).validate_python(v)))
]


DNS_LABEL_REGEX = r"[a-zA-Z0-9][a-zA-Z0-9-]*?[a-zA-Z0-9]"
DOMAIN_NAME_REGEX = (
    r"^" +
    r"(" + DNS_LABEL_REGEX + r"\.)+" +
    DNS_LABEL_REGEX +
    r"$"
)
#: Type for validating a string as a domain name
DomainName = t.Annotated[str, StringConstraints(pattern = DOMAIN_NAME_REGEX)]


class ConsulConfig(Section):
    """
    Model for the Consul configuration section.
    """
    #: The address of the Consul server
    address: str = "127.0.0.1"
    #: The port of the Consul server
    port: int = 8500
    #: The timeout to use with Consul blocking queries
    #: By default, we use many short queries as this results in fewer pool timeouts
    #: in systems with a large volume of services
    blocking_query_timeout: int = 1
    #: The time to wait between Consul queries
    query_interval: int = 5
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


class ForwardedQueryParamRule(te.TypedDict, total = False):
    """
    Model for a forwarded query parameter rule.
    """
    value: NonEmptyString
    pattern: NonEmptyString


class ForwardedQueryParam(te.TypedDict, total = False):
    """
    Model for a forwarded query parameter.
    """
    name: NonEmptyString
    default: t.List[NonEmptyString]
    allow: t.List[ForwardedQueryParamRule]


class OIDCConfig(Section):
    """
    Model for the ingress OIDC configuration section.
    """
    #: Indicates if discovery should be used for clients that don't specify an OIDC issuer
    #: This allows an external controller to place secrets in the Zenith namespace
    #: containing OIDC credentials to use for each service
    discovery_enabled: bool = False
    #: The template to use for the names of discovery secrets
    discovery_secret_name_template: NonEmptyString = "oidc-discovery-{service_name}"
    #: The template to use for the secret containing the cookie secret for the OAuth2 proxy
    oauth2_proxy_cookie_secret_template: NonEmptyString = "oidc-cookie-{service_name}"
    #: The query parameters that are passed to the IDP in the authorize request
    #: For example, Keycloak allows a kc_idp_hint parameter that can be used to
    #: pre-select an identity provider
    #: See https://oauth2-proxy.github.io/oauth2-proxy/docs/configuration/alpha-config#loginurlparameter
    forwarded_query_params: t.List[ForwardedQueryParam] = Field(default_factory = list)
    #: The headers to inject into the request from claims in the ID token
    #: The special claims id_token and access_token represent the ID and access tokens
    inject_request_headers: t.Dict[str, str] = Field(default_factory = dict)


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
    #: Indicates if the ingress controller is itself behind a proxy that is terminating TLS
    terminated_at_proxy: bool = False
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
    #: Indicates whether the subdomain should be used as a path prefix
    subdomain_as_path_prefix: bool = False
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
    default_timeout: t.Union[int, NonEmptyString] = "2m"
    #: The executable to use
    #: By default, we assume Helm is on the PATH
    executable: NonEmptyString = "helm"
    #: The maximum number of revisions to retain in the history of releases
    history_max_revisions: int = 3
    #: Indicates whether to verify TLS when pulling charts
    insecure_skip_tls_verify: bool = False
    #: The directory to use for unpacking charts
    #: By default, the system temporary directory is used
    unpack_directory: t.Optional[str] = None


class KubernetesConfig(Section):
    """
    Model for the Kubernetes configuration section.
    """
    #: The field manager name to use for server-side apply
    easykube_field_manager: NonEmptyString = "zenith-sync"

    #: The namespace that the sync component is running in
    self_namespace: str
    #: The namespace to create Zenith service resources in
    target_namespace: str = "zenith-services"

    #: The API group to use for CRD resources
    crd_api_group: str = "zenith.stackhpc.com"
    #: The categories for the CRD resources
    crd_categories: t.List[str] = Field(default_factory = lambda: ["zenith"])
    #: The sleep interval for the endpoint checker
    #: Assuming the sync component is up, then the maximum time after the last heartbeart
    #: that a dead endpoint will still be included in the endpoints of a service is the
    #: ttl of the endpoint plus this interval
    crd_endpoint_check_interval: t.Annotated[int, Field(gt = 0)] = 10

    #: The Helm chart repo, name and version to use for the zenith-service chart
    #: By default, this points to a local chart that is baked into the Docker image
    service_chart_name: NonEmptyString = "/charts/zenith-service"
    service_chart_repo: t.Optional[AnyHttpUrl] = None
    service_chart_version: t.Optional[SemVerVersion] = None
    #: Default values for releases of the service chart
    service_default_values: t.Dict[str, t.Any] = Field(default_factory = dict)

    #: The label used to indicate a managed resource
    created_by_label: str = "app.kubernetes.io/created-by"
    #: The label used to indicate the corresponding Zenith service for a resource
    service_name_label: str = "zenith.stackhpc.com/service-name"
    #: The annotation used to record that a secret is a mirror of another secret
    tls_mirror_annotation: str = "zenith.stackhpc.com/mirrors"
    #: The maximum number of concurrent reconciliations
    reconciliation_max_concurrency: t.Annotated[int, Field(gt = 0)] = 20
    #: The maximum delay between retries when backing off
    reconciliation_max_backoff: t.Annotated[int, Field(gt = 0)] = 60
    #: The ingress configuration
    ingress: IngressConfig
    #: The Helm client configuration
    helm_client: HelmClientConfiguration = Field(default_factory = HelmClientConfiguration)


class SyncConfig(
    Configuration,
    default_path = "/etc/zenith/sync.yaml",
    path_env_var = "ZENITH_SYNC_CONFIG",
    env_prefix = "ZENITH_SYNC"
):
    """
    Configuration model for the zenith-sync package.
    """
    #: The logging configuration
    logging: LoggingConfiguration = Field(default_factory = LoggingConfiguration)

    #: The name of the processor type to use
    processor_type: NonEmptyString = "helm"
    #: The name of the store type to use
    store_type: NonEmptyString = "crd"

    #: The Consul configuration
    consul: ConsulConfig = Field(default_factory = ConsulConfig)
    #: The Kubernetes configuration
    kubernetes: KubernetesConfig = Field(default_factory = KubernetesConfig)
