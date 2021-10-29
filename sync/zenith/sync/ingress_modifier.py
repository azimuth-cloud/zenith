INGRESS_MODIFIERS_ENTRY_POINT_GROUP = "zenith.sync.ingress_modifiers"


class IngressModifier:
    """
    Base class for an ingress modifier.
    """
    def configure_backend_protocol(self, ingress, protocol):
        """
        Applies any configuration required to enable the specified backend protocol
        for the specified ingress. The ingress should be modified in-place.
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
    BACKEND_PROTOCOL_ANNOTATION = "nginx.ingress.kubernetes.io/backend-protocol"
    AUTH_TLS_SECRET_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-secret"
    AUTH_TLS_VERIFY_CLIENT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-verify-client"
    AUTH_TLS_PASS_CERT_ANNOTATION = "nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream"

    def configure_backend_protocol(self, ingress, protocol):
        ingress["metadata"]["annotations"][self.BACKEND_PROTOCOL_ANNOTATION] = protocol.upper()

    def configure_tls_client_certificates(self, ingress, namespace, secret_name):
        ingress["metadata"]["annotations"].update({
            self.AUTH_TLS_SECRET_ANNOTATION: f"{namespace}/{secret_name}",
            self.AUTH_TLS_VERIFY_CLIENT_ANNOTATION: "optional",
            self.AUTH_TLS_PASS_CERT_ANNOTATION: "true",
        })
