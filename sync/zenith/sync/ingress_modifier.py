INGRESS_MODIFIERS_ENTRY_POINT_GROUP = "zenith.sync.ingress_modifiers"


class IngressModifier:
    """
    Base class for an ingress modifier.
    """
    def configure_defaults(self, ingress):
        """
        Applies any default configuration to the given ingress.
        """

    def configure_backend_protocol(self, ingress, protocol):
        """
        Applies any configuration required to enable the specified backend protocol
        for the specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError

    def configure_read_timeout(self, ingress, timeout):
        """
        Applies any configuration required to set the specified read timeout for the
        specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError

    def configure_tls_client_certificates(self, ingress, namespace, secret_name):
        """
        Applies any configuration required to enable the handling of TLS client certificates
        for the specified ingress. The ingress should be modified in-place.
        """
        raise NotImplementedError


class NginxIngressModifier(IngressModifier):
    """
    Ingress modifier for the Nginx Ingress Controller.
    """
    DEFAULT_ANNOTATIONS = {
        "nginx.ingress.kubernetes.io/proxy-buffering": "off",
    }
    AUTH_TLS_SECRET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-secret"
    AUTH_TLS_VERIFY_CLIENT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-verify-client"
    AUTH_TLS_PASS_CERT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"
    BACKEND_PROTOCOL_ANNOTATION = "nginx.ingress.kubernetes.io/backend-protocol"
    READ_TIMEOUT_ANNOTATION = "nginx.ingress.kubernetes.io/proxy-read-timeout"

    def configure_defaults(self, ingress):
        ingress["metadata"]["annotations"].update(self.DEFAULT_ANNOTATIONS)

    def configure_backend_protocol(self, ingress, protocol):
        ingress["metadata"]["annotations"][self.BACKEND_PROTOCOL_ANNOTATION] = protocol.upper()

    def configure_read_timeout(self, ingress, timeout):
        ingress["metadata"]["annotations"][self.READ_TIMEOUT_ANNOTATION] = str(timeout)

    def configure_tls_client_certificates(self, ingress, namespace, secret_name):
        ingress["metadata"]["annotations"].update({
            self.AUTH_TLS_SECRET_ANNOTATION: f"{namespace}/{secret_name}",
            self.AUTH_TLS_VERIFY_CLIENT_ANNOTATION: "optional",
            self.AUTH_TLS_PASS_CERT_ANNOTATION: "true",
        })
